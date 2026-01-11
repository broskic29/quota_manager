import asyncio
import threading
import datetime as dt
import logging

from time import sleep

import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm

ACCOUNT_BILLING_DAY = 7
UPDATE_INTERVAL = 10
UTC_OFFSET = 2
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


def wipe_scheduler():
    while True:
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

        qm.reset_throttling_and_packet_dropping()
        log.info("Throttling and packet dropping reset.")


def usage_updater():
    while True:
        sleep(UPDATE_INTERVAL)

        log.debug("Updating user byte totals...")
        usage_dict = qm.update_all_users_bytes()
        log.debug(usage_dict)

        log.debug("Enforcing quotas...")
        quota_dict = qm.enforce_quotas_all_users(throttling=False)
        log.debug(quota_dict)

        log.debug("Updating persistent nft sets...")
        qm.ensure_set_persistence()


async def daemon():
    # Run the scheduler in the background
    t_wipe_scheduler = threading.Thread(target=wipe_scheduler, daemon=True)
    t_usage_updater = threading.Thread(target=usage_updater, daemon=True)

    t_wipe_scheduler.start()
    t_usage_updater.start()

    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        log.info("Usage daemon cancelled")
