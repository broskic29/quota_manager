import asyncio
import datetime as dt

import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm

ACCOUNT_BILLING_DAY = 7
UPDATE_INTERVAL = 10
UTC_OFFSET = 2
ONE_DAY = 1


async def wipe_scheduler():
    while True:
        tz = dt.timezone(dt.timedelta(hours=UTC_OFFSET))
        now = dt.datetime.now(tz)

        zero_hour = dt.datetime(now.year, now.month, now.day, tzinfo=tz)

        # ---------------------
        # Schedule next daily task
        # ---------------------

        next_daily = zero_hour + dt.timedelta(days=ONE_DAY)

        daily_delay = next_daily - now

        await asyncio.sleep(daily_delay.seconds)

        # After waking up, determine which tasks to run
        now = dt.datetime.now(tz)

        if now.day == ACCOUNT_BILLING_DAY:
            sqlm.usage_monthly_wipe()

        sqlm.usage_daily_wipe()

        qm.reset_throttling()
        # Add another function call: _reset_user_packet_dropping()


async def usage_updater():
    while True:
        await asyncio.sleep(UPDATE_INTERVAL)

        qm.update_all_users_bytes()

        qm.enforce_quotas_all_users()


async def daemon():
    # Run the scheduler in the background
    await wipe_scheduler()
    await usage_updater()
