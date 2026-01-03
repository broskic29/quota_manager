import logging
from python_arptable import get_arp_table

from quota_manager import sql_management as sqlm
from quota_manager import nftables_management as nftm
from quota_manager import sqlite_helper_functions as sqlh


log = logging.getLogger(__name__)


def mac_from_ip(ip):
    arp_table = get_arp_table()
    mac_address = None
    for entry in arp_table:
        if entry["IP address"] == ip:
            mac_address = entry["HW address"]

    if mac_address is None:
        log.error(f"No MAC address found associated with ip {ip}.")
        raise KeyError(f"No MAC address found associated with ip {ip}.")

    return mac_address


def is_user_authenticated(username, user_mac):
    in_group = sqlm.check_if_user_in_any_group(
        username, db_path=sqlh.USAGE_TRACKING_DB_PATH
    )
    mac_in_set = nftm.check_if_elem_in_set(
        user_mac, nftm.TABLE_FAMILY, nftm.CAPTIVE_TABLE_NAME, nftm.AUTH_SET_NAME
    )
    return in_group and mac_in_set


def fetch_user_bytes(username):
    user_mac = sqlm.fetch_user_mac_address_usage(username)

    try:
        user_bytes = nftm.get_bytes_from_user(user_mac)
    except nftm.NFTSetMissingElementError:
        log.warning(
            f"NFTables authorized users set empty even though users are logged in!"
        )
        log.debug(
            f"Attempting to add user {username}'s MAC address to authorized users set..."
        )
        mac_address = sqlm.fetch_user_mac_address_usage(username)
        mac_update(None, mac_address, username)
        log.debug(
            f"Successfully added user {username}'s MAC address to authorized users set."
        )
    except TypeError:
        log.warning(
            f"Mismatch between user {username} MAC address in database and in NFTables. Attempting to reconcile..."
        )
        delete_mac_from_set(user_mac)
        add_user_to_set(username)
        log.debug(
            f"Successfully added user {username}'s MAC address to authorized users set."
        )

    user_bytes = nftm.get_bytes_from_user(user_mac)

    return user_bytes


def update_all_users_bytes(db_path=sqlh.USAGE_TRACKING_DB_PATH):

    usage_dict = {}
    usernames = sqlm.fetch_all_usernames_usage(db_path)

    for username in usernames:
        if sqlm.check_if_user_logged_in(username):
            user_bytes = fetch_user_bytes(username)
            sqlm.update_user_bytes_usage(user_bytes, username, db_path)
            usage_dict[username] = user_bytes
        else:
            log.debug(f"User {username} not logged in. Ignoring for usage check.")

    return usage_dict


def reset_throttling(db_path=sqlh.USAGE_TRACKING_DB_PATH):

    nftm.flush_set(nftm.TABLE_FAMILY, nftm.THROTTLE_TABLE_NAME, nftm.THROTTLE_SET_NAME)

    usernames = sqlm.fetch_all_usernames_usage(db_path)

    for username in usernames:

        try:
            mac_address = sqlm.fetch_user_mac_address_usage(username)
        except KeyError:
            mac_address = None

        if mac_address is None:
            log.error(
                f"ERROR: failed to reset throttling for user {username}. User MAC address not found."
            )
            raise KeyError(f"No MAC address found for user {username}")

        nftm.operation_on_set_element(
            "add",
            nftm.TABLE_FAMILY,
            nftm.THROTTLE_TABLE_NAME,
            nftm.HIGH_SPEED_SET_NAME,
            mac_address,
        )


def enforce_quotas_all_users(db_path=sqlh.USAGE_TRACKING_DB_PATH):

    quota_dict = {"under_quota": [], "over_quota": []}

    usernames = sqlm.fetch_all_usernames_usage(db_path)

    for username in usernames:
        if sqlm.check_if_daily_bytes_exceeds_high_speed_quota_for_user_usage(
            username, db_path
        ):
            if username not in quota_dict["over_quota"]:
                quota_dict["over_quota"].append(username)
            try:
                mac_address = sqlm.fetch_user_mac_address_usage(username)
            except KeyError:
                mac_address = None

            if mac_address is None:
                log.error(
                    f"ERROR: failed to reset throttling for user {username}. User MAC address not found."
                )
                raise KeyError(f"No MAC address found for user {username}")
            # Add error catching here
            nftm.operation_on_set_element(
                "add",
                nftm.TABLE_FAMILY,
                nftm.THROTTLE_TABLE_NAME,
                nftm.THROTTLE_SET_NAME,
                mac_address,
            )
            nftm.operation_on_set_element(
                "delete",
                nftm.TABLE_FAMILY,
                nftm.THROTTLE_TABLE_NAME,
                nftm.HIGH_SPEED_SET_NAME,
                mac_address,
            )
        else:
            if username not in quota_dict["under_quota"]:
                quota_dict["under_quota"].append(username)

    return quota_dict


def add_mac_to_set(user_mac):
    nftm.operation_on_set_element(
        "add",
        nftm.TABLE_FAMILY,
        nftm.CAPTIVE_TABLE_NAME,
        nftm.AUTH_SET_NAME,
        user_mac,
    )


def delete_mac_from_set(user_mac):
    nftm.operation_on_set_element(
        "delete",
        nftm.TABLE_FAMILY,
        nftm.CAPTIVE_TABLE_NAME,
        nftm.AUTH_SET_NAME,
        user_mac,
    )


def add_user_to_set(username):
    try:
        user_mac = sqlm.fetch_user_mac_address_usage(username)
    except sqlm.UserNameError:
        log.debug(f"User {username} does not exist.")
        user_mac = None

    if user_mac is not None:
        add_mac_to_set(user_mac)


def delete_user_from_set(username):
    try:
        user_mac = sqlm.fetch_user_mac_address_usage(username)
    except sqlm.UserNameError:
        log.debug(f"User {username} does not exist.")
        user_mac = None

    if user_mac is not None:
        delete_mac_from_set(user_mac)


def unauthorize_user(username):
    try:
        user_mac = sqlm.fetch_user_mac_address_usage(username)
    except sqlm.UserNameError:
        log.debug(f"User {username} does not exist.")
        user_mac = None

    if user_mac is not None:
        sqlm.delete_user_usage(username)
        delete_mac_from_set(user_mac)
        log.info(f"Successfully unauthorized user {username}.")


def delete_user_from_system(username):
    try:
        user_mac = sqlm.fetch_user_mac_address_usage(username)
    except sqlm.UserNameError:
        log.debug(f"User {username} does not exist.")
        user_mac = None
    if user_mac is not None:
        sqlm.delete_user_usage(username)
        sqlm.delete_user_radius(username)
        delete_mac_from_set(user_mac)
        log.info(f"Successfully unauthorized user {username}.")


def mac_update(old_mac, new_mac, username):
    # if user has dynamic mac, remove old one from set
    if old_mac != new_mac and old_mac is not None:

        log.debug("User has dynamic MAC, removing old MAC address from set...")

        # has to be part of the daemon process to regularly update amount of bytes used total by user.
        # This just calls the function to ensure that nothing is lost when the MAC address is updated.
        user_bytes = fetch_user_bytes(username)
        sqlm.update_user_bytes_usage(user_bytes, username, mac_reset=True)

        nftm.operation_on_set_element(
            "delete",
            nftm.TABLE_FAMILY,
            nftm.CAPTIVE_TABLE_NAME,
            nftm.AUTH_SET_NAME,
            old_mac,
        )

    # Add nftables rule to switch this mac to authorized set
    nftm.operation_on_set_element(
        "add",
        nftm.TABLE_FAMILY,
        nftm.CAPTIVE_TABLE_NAME,
        nftm.AUTH_SET_NAME,
        new_mac,
    )
