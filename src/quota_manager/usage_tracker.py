import threading
import datetime as dt
import logging

import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm

from quota_manager.sqlite_helper_functions import UTC_OFFSET

USAGE_UPDATE_INTERVAL = 1
ONE_DAY = 1
ONE_MONTH = 1

log = logging.getLogger(__name__)


def daily_delay_calc(now, tz):
    zero_hour = dt.datetime(now.year, now.month, now.day, tzinfo=tz)

    next_daily = zero_hour + dt.timedelta(days=ONE_DAY)

    log.info(f"Next daily wipe set for {next_daily}.")

    daily_delay = next_daily - now

    return daily_delay


def monthly_delay_calc(now, tz):
    zero_hour = dt.datetime(now.year, now.month, now.day, tzinfo=tz)

    next_monthly = zero_hour + dt.timedelta(days=(32 - now.day))
    next_monthly = next_monthly.replace(day=qm.ACCOUNT_BILLING_DAY)

    log.info(f"Next monthly wipe set for {next_monthly}.")

    monthly_delay = next_monthly - now

    return monthly_delay


def event_scheduler(stop_event: threading.Event):
    while not stop_event.is_set():

        tz = dt.timezone(dt.timedelta(hours=UTC_OFFSET))
        now = dt.datetime.now(tz)

        daily_delay = daily_delay_calc(now, tz)
        monthly_delay = monthly_delay_calc(now, tz)

        next_delay = min(daily_delay, monthly_delay)

        if stop_event.wait(next_delay.total_seconds()):
            break

        # After waking up, determine which tasks to run
        now = dt.datetime.now(tz)

        if now.day == qm.ACCOUNT_BILLING_DAY:
            try:
                monthly_events()
                qm.update_monthly_wipe()
            except Exception as e:
                log.debug(
                    f"event_scheduler: Failed to execute monthly events, error: {e}"
                )

        try:
            daily_events(now)
            qm.update_system_date(now)
        except Exception as e:
            log.debug(f"event_scheduler: Failed to execute daily events, error: {e}")


def daily_events(now):

    if not qm.RESET_LOCK.acquire(blocking=False):
        log.debug(f"daily_events: Acquired RESET_LOCK")
        return  # reset in progress, skip tick
    try:
        if not qm.QUOTA_LOCK.acquire(timeout=0.1):
            log.debug(f"daily_events: Acquired QUOTA_LOCK")
            return  # admin is changing groups/quotas; skip tick
        try:
            sqlm.usage_daily_wipe()
            log.info(f"Daily usage wipe, {now}")

            qm.log_out_all_users()
            log.info("All users logged out.")

            qm.nftm_flush_set_ghosts()
            log.info("Nftm set ghosts flushed.")

            qm.wipe_ip_neigh_db()
            log.info("IP neigh db wiped")

            qm.reset_throttling_and_packet_dropping_all_users()
            log.info("Throttling and packet dropping reset for all users.")

            group_quotas_dict = qm.calculate_hypothetical_group_quotas_for_today(
                now=now, reset_day=qm.ACCOUNT_BILLING_DAY
            )

            qm.apply_new_quotas(group_quotas_dict)
            log.info("New daily quotas applied.")

            qm.update_daily_byte_budget(now)
            log.info("Quota byte budget updated.")

        except Exception as e:
            log.error(f"daily_events: Failed to execute daily events, error: {e}")
            raise
        finally:
            qm.QUOTA_LOCK.release()
            log.debug(f"daily_events: Released QUOTA_LOCK")
    finally:
        qm.RESET_LOCK.release()
        log.debug(f"daily_events: Released RESET_LOCK")


def monthly_events():

    if not qm.RESET_LOCK.acquire(blocking=False):
        return  # reset in progress, skip tick
    try:
        if not qm.QUOTA_LOCK.acquire(timeout=0.1):
            return  # admin is changing groups/quotas; skip tick
        try:
            sqlm.usage_monthly_wipe()
        except Exception as e:
            log.error(f"monthly_events: Failed to execute daily events, error: {e}")
            raise
        finally:
            qm.QUOTA_LOCK.release()
            log.debug(f"monthly_events: Released QUOTA_LOCK")
    finally:
        qm.RESET_LOCK.release()
        log.debug(f"monthly_events: Released RESET_LOCK")


def usage_updater(stop_event: threading.Event):

    # Initialize continuously updated variables
    quota_dict = {}
    usage_dict = {}

    num_users = 0
    num_groups = 0

    config = sqlm.fetch_active_config()

    if config is None:
        log.warning("usage_updater: System config not loaded.")
        raise RuntimeError("usage_updater: System config not loaded.")

    system_name = config["system_name"]

    qm.initialize_session_start_bytes_for_system(system_name=system_name)
    sqlm.wipe_session_total_bytes(system_name=system_name)

    while not stop_event.is_set():
        if stop_event.wait(USAGE_UPDATE_INTERVAL):
            break

        reset_lock_acquired = qm.RESET_LOCK.acquire(blocking=False)
        if not reset_lock_acquired:
            continue  # reset in progress, skip tick
        # log.debug(f"usage_updater: Acquired RESET_LOCK")
        try:
            quota_lock_acquired = qm.QUOTA_LOCK.acquire(timeout=0.1)
            if not quota_lock_acquired:
                continue  # admin is changing groups/quotas; skip tick
            # log.debug(f"usage_updater: Acquired QUOTA_LOCK")
            try:
                tz = dt.timezone(dt.timedelta(hours=UTC_OFFSET))
                now = dt.datetime.now(tz)

                try:
                    system_daily_wiped = qm.system_daily_wipe_check(now)

                    if not system_daily_wiped:
                        log.info(
                            "System daily wipe check returned false, wiping system..."
                        )

                        daily_events(now)
                        qm.update_system_date(now)

                except Exception as e:
                    log.debug(
                        f"usage_updater: Failed to execute daily events, error: {e}"
                    )
                    raise

                try:
                    system_monthly_wiped = qm.system_monthly_wipe_check()
                    if not system_monthly_wiped:
                        log.debug(
                            "System monthly wipe check returned false, wiping system..."
                        )

                        monthly_events()
                        qm.update_monthly_wipe()
                except Exception as e:
                    log.debug(
                        f"usage_updater: Failed to execute monthly events, error: {e}"
                    )
                    raise

                log.debug("Updating user byte totals...")
                usage_dict = qm.update_all_users_bytes(usage_dict)

                log.debug("Updating quota information for all users...")
                quota_dict = qm.update_quota_information_all_users(quota_dict)
                log.debug(quota_dict)

                log.debug("Enforcing quotas for all users...")
                qm.enforce_quotas_all_users(throttling=False)

                log.debug("Updating system byte totals...")
                qm.update_total_system_bytes()

                log.debug("Updating num entities system state...")
                num_users, num_groups = qm.update_num_entities_system_state(
                    num_users, num_groups
                )

            except qm.QuotaAllottmentError as e:
                log.error(f"usage_updater: Failed to execute usage update, error: {e}")
            finally:
                if quota_lock_acquired:
                    qm.QUOTA_LOCK.release()
                    # log.debug(f"usage_updater: Released QUOTA_LOCK")
        except Exception as e:
            log.error(f"usage_updater: Failed to execute usage update, error: {e}")
            stop_event.set()
            raise
        finally:
            if reset_lock_acquired:
                qm.RESET_LOCK.release()
                # log.debug(f"usage_updater: Released RESET_LOCK")


def start_usage_tracking(stop_event: threading.Event):
    """Start the wipe scheduler and usage updater threads"""
    t_wipe_scheduler = threading.Thread(
        target=event_scheduler, args=(stop_event,), daemon=True
    )
    t_usage_updater = threading.Thread(
        target=usage_updater, args=(stop_event,), daemon=True
    )

    log.info("Usage tracking threads started")
    return [t_wipe_scheduler, t_usage_updater]
