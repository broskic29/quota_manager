import threading
import datetime as dt
import logging

from time import sleep

import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm

from quota_manager.sqlite_helper_functions import UTC_OFFSET

ACCOUNT_BILLING_DAY = 7
UPDATE_INTERVAL = 10
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
    next_monthly = next_monthly.replace(day=ACCOUNT_BILLING_DAY)

    log.info(f"Next monthly wipe set for {next_monthly}.")

    monthly_delay = next_monthly - now

    return monthly_delay


def wipe_scheduler(stop_event: threading.Event):
    while not stop_event.is_set():
        tz = dt.timezone(dt.timedelta(hours=UTC_OFFSET))
        now = dt.datetime.now(tz)

        daily_delay = daily_delay_calc(now, tz)
        monthly_delay = monthly_delay_calc(now, tz)

        next_delay = min(daily_delay, monthly_delay)

        sleep(next_delay.seconds)

        # After waking up, determine which tasks to run
        now = dt.datetime.now(tz)

        if now.day == ACCOUNT_BILLING_DAY:
            sqlm.usage_monthly_wipe()
            log.info("Monthly wipe complete.")

        sqlm.usage_daily_wipe()
        log.info("Daily wipe complete.")

        qm.log_out_all_users()
        log.info("All users logged out.")

        qm.wipe_ip_neigh_db()
        log.info("IP neigh db wiped.")

        qm.reset_throttling_and_packet_dropping_all_users()
        log.info("Throttling and packet dropping reset.")


def usage_updater(stop_event: threading.Event):

    quota_dict = {}

    while not stop_event.is_set():
        sleep(UPDATE_INTERVAL)

        if stop_event.is_set():
            break

        log.debug("Updating user byte totals...")
        usage_dict = qm.update_all_users_bytes()
        log.debug(usage_dict)

        log.debug("Updating quota information for all users...")
        quota_dict = qm.update_quota_information_all_users(quota_dict)

        log.debug("Enforcing quotas for all users...")
        qm.enforce_quotas_all_users(throttling=False)


def start_usage_tracking(stop_event: threading.Event):
    """Start the wipe scheduler and usage updater threads"""
    t_wipe_scheduler = threading.Thread(
        target=wipe_scheduler, args=(stop_event,), daemon=True
    )
    t_usage_updater = threading.Thread(
        target=usage_updater, args=(stop_event,), daemon=True
    )

    log.info("Usage tracking threads started")
    return [t_wipe_scheduler, t_usage_updater]
