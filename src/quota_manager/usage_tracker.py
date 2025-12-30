import asyncio
import datetime as dt

import quota_manager.sql_management as sqlm
import quota_manager.nftables_management as nftm

ACCOUNT_BILLING_DAY = 7
UPDATE_INTERVAL = 10


def _reset_throttling(db_path=sqlm.USAGE_TRACKING_DB_PATH):

    nftm.flush_set(nftm.TABLE_FAMILY, nftm.THROTTLE_TABLE_NAME, nftm.THROTTLE_SET_NAME)

    usernames = sqlm.fetch_all_usernames_usage(db_path)

    for username in usernames:

        mac_address = sqlm.fetch_user_mac_address_usage(username, db_path)

        nftm.operation_on_set_element(
            "add",
            nftm.TABLE_FAMILY,
            nftm.THROTTLE_TABLE_NAME,
            nftm.HIGH_SPEED_SET_NAME,
            mac_address,
        )


def _enforce_quotas_all_users(db_path=sqlm.USAGE_TRACKING_DB_PATH):

    usernames = sqlm.fetch_all_usernames_usage(db_path)

    for username in usernames:
        if sqlm.check_if_daily_bytes_exceeds_high_speed_quota_for_user_usage(
            username, db_path
        ):
            mac_address = sqlm.fetch_user_mac_address_usage(username, db_path)
            # Add error catching here
            nftm.operation_on_set_element(
                "delete",
                nftm.TABLE_FAMILY,
                nftm.THROTTLE_TABLE_NAME,
                nftm.HIGH_SPEED_SET_NAME,
                mac_address,
            )
            nftm.operation_on_set_element(
                "add",
                nftm.TABLE_FAMILY,
                nftm.THROTTLE_TABLE_NAME,
                nftm.THROTTLE_SET_NAME,
                mac_address,
            )


async def wipe_scheduler():
    while True:
        tz = dt.timezone(dt.timedelta(hours=2))
        now = dt.datetime.now(tz)

        zero_hour = dt.datetime(now.year, now.month, now.day, tzinfo=tz)

        # ---------------------
        # Schedule next daily task
        # ---------------------

        next_daily = zero_hour + dt.timedelta(days=1)

        daily_delay = next_daily - now

        await asyncio.sleep(daily_delay.seconds)

        # After waking up, determine which tasks to run
        now = dt.datetime.now(tz)

        if now.day == ACCOUNT_BILLING_DAY:
            sqlm.usage_monthly_wipe()

        sqlm.usage_daily_wipe()

        _reset_throttling()
        # Add another function call: _reset_user_packet_dropping()


async def usage_updater():
    while True:
        await asyncio.sleep(UPDATE_INTERVAL)

        sqlm.update_all_users_bytes_usage()

        _enforce_quotas_all_users()


async def daemon():
    # Run the scheduler in the background
    await wipe_scheduler()
    await usage_updater()
