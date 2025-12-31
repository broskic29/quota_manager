from quota_manager import sql_management as sqlm
from quota_manager import nftables_management as nftm
from quota_manager import sqlite_helper_functions as sqlh


def fetch_user_bytes(username):
    user_mac = sqlm.fetch_user_mac_address_usage(username)
    user_bytes = nftm.get_bytes_from_user(user_mac)
    return user_bytes


def update_all_users_bytes(db_path=sqlh.USAGE_TRACKING_DB_PATH):

    usernames = sqlm.fetch_all_usernames_usage(db_path)

    for username in usernames:
        user_bytes = fetch_user_bytes(username)
        sqlm.update_user_bytes_usage(user_bytes, username, db_path)


def reset_throttling(db_path=sqlh.USAGE_TRACKING_DB_PATH):

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


def enforce_quotas_all_users(db_path=sqlh.USAGE_TRACKING_DB_PATH):

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
