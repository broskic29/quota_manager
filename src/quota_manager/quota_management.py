import logging
import pickle
from python_arptable import get_arp_table
from pathlib import Path

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
    try:
        mac_in_set = nftm.check_if_elem_in_set(
            user_mac, nftm.TABLE_FAMILY, nftm.TABLE_NAME, nftm.AUTH_SET_NAME
        )
    except KeyError:
        log.debug(f"MAC address {user_mac} not in nft set.")
        return False
    logged_in = sqlm.check_if_user_logged_in(username)
    return in_group and mac_in_set and logged_in


def fetch_user_bytes(username):
    log.debug(f"Fetching user bytes for user {username}...")
    try:
        user_mac = sqlm.fetch_user_mac_address_usage(username)
    except nftm.MACAddressError:
        log.debug(f"No MAC address for user {username}.")
        return None

    try:
        user_bytes = nftm.get_bytes_from_user(user_mac)
    except nftm.NFTSetMissingElementError:
        log.debug(f"Authorized users set empty.")
        return None

    log.debug(f"User bytes: {user_bytes}")

    return user_bytes


def initialize_session_start_bytes(user_mac):
    log.debug(f"Initializing session start bytes for user at {user_mac}")
    try:
        session_start_bytes = nftm.get_bytes_from_user(user_mac)
    except (nftm.NFTSetMissingElementError, nftm.MACAddressError):
        log.debug(f"MAC address {user_mac} not in set.")
        return 0
    log.debug(f"Session start bytes: {session_start_bytes}")
    return session_start_bytes


def calculate_byte_delta(user_bytes, username, db_path=sqlh.USAGE_TRACKING_DB_PATH):

    session_total_bytes = sqlm.fetch_session_total_bytes(username, db_path)
    session_start_bytes = sqlm.fetch_session_start_bytes(username)

    byte_delta = (user_bytes - session_start_bytes) - session_total_bytes

    log.debug(f"Byte delta: {byte_delta}")

    return byte_delta


def update_user_bytes(username, usage_dict={}, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    if sqlm.check_if_user_logged_in(username):
        user_bytes = fetch_user_bytes(username)
        if user_bytes is not None:
            byte_delta = calculate_byte_delta(user_bytes, username)
            sqlm.update_user_bytes_usage(byte_delta, username, db_path)
            usage_dict[username] = user_bytes
    else:
        log.debug(f"User {username} not logged in. Ignoring for usage check.")

    return usage_dict


def update_all_users_bytes(db_path=sqlh.USAGE_TRACKING_DB_PATH):

    usage_dict = {}
    usernames = sqlm.fetch_all_usernames_usage(db_path)

    for username in usernames:
        usage_dict = update_user_bytes(username, usage_dict)

    return usage_dict


def reset_throttling_and_packet_dropping(db_path=sqlh.USAGE_TRACKING_DB_PATH):

    nftm.flush_set(nftm.TABLE_FAMILY, nftm.TABLE_NAME, nftm.THROTTLE_SET_NAME)

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
            "delete",
            nftm.TABLE_FAMILY,
            nftm.TABLE_NAME,
            nftm.THROTTLE_SET_NAME,
            mac_address,
        )

        nftm.operation_on_set_element(
            "add",
            nftm.TABLE_FAMILY,
            nftm.TABLE_NAME,
            nftm.HIGH_SPEED_SET_NAME,
            mac_address,
        )

        nftm.operation_on_set_element(
            "delete",
            nftm.TABLE_FAMILY,
            nftm.TABLE_NAME,
            nftm.DROP_SET_NAME,
            mac_address,
        )


def enforce_quotas_all_users(throttling: bool, db_path=sqlh.USAGE_TRACKING_DB_PATH):

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

            if throttling:
                nftm.operation_on_set_element(
                    "add",
                    nftm.TABLE_FAMILY,
                    nftm.TABLE_NAME,
                    nftm.THROTTLE_SET_NAME,
                    mac_address,
                )
                nftm.operation_on_set_element(
                    "delete",
                    nftm.TABLE_FAMILY,
                    nftm.TABLE_NAME,
                    nftm.HIGH_SPEED_SET_NAME,
                    mac_address,
                )
            else:
                nftm.operation_on_set_element(
                    "delete",
                    nftm.TABLE_FAMILY,
                    nftm.TABLE_NAME,
                    nftm.DROP_SET_NAME,
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
        nftm.TABLE_NAME,
        nftm.AUTH_SET_NAME,
        user_mac,
    )


def delete_mac_from_set(user_mac):
    nftm.operation_on_set_element(
        "delete",
        nftm.TABLE_FAMILY,
        nftm.TABLE_NAME,
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

    sqlm.delete_user_usage(username)

    if user_mac is not None:
        delete_mac_from_set(user_mac)

    log.info(f"Successfully unauthorized user {username}.")


def log_out_user(username, user_mac=None):

    if user_mac is None:
        try:
            user_mac = sqlm.fetch_user_mac_address_usage(username)
        except sqlm.UserNameError:
            log.debug(f"User {username} does not exist.")

    if user_mac is not None:
        if not check_which_user_logged_in_for_mac_address(user_mac):
            delete_mac_from_set(user_mac)
            log.info(
                f"Successfully deleted user {username} MAC address ({user_mac}) from set"
            )

    sqlm.logout_user_usage(username)

    log.info(f"Successfully logged out user {username}.")


def delete_user_from_system(username):

    user_exists_usage = sqlm.check_if_user_exists(username)
    user_exists_radius = sqlm.check_if_user_exists(
        username, table_name="radcheck", db_path=sqlh.RADIUS_DB_PATH
    )

    if user_exists_usage:
        user_mac = sqlm.fetch_user_mac_address_usage(username)
        sqlm.delete_user_usage(username)
        delete_mac_from_set(user_mac)

    if user_exists_radius:
        sqlm.delete_user_radius(username)

    log.info(f"Successfully unauthorized user {username}.")


def mac_update(old_mac, new_mac):
    # if user has dynamic mac, remove old one from set
    if old_mac != new_mac and old_mac is not None:

        log.debug("User has dynamic MAC, removing old MAC address from set...")

        nftm.operation_on_set_element(
            "delete",
            nftm.TABLE_FAMILY,
            nftm.TABLE_NAME,
            nftm.AUTH_SET_NAME,
            old_mac,
        )

    # Add nftables rule to switch this mac to authorized set
    nftm.operation_on_set_element(
        "add",
        nftm.TABLE_FAMILY,
        nftm.TABLE_NAME,
        nftm.AUTH_SET_NAME,
        new_mac,
    )


def check_which_user_logged_in_for_mac_address(mac_address):
    usernames = sqlm.get_usernames_from_mac_address_usage(mac_address)

    if usernames is not None:
        for username in usernames:
            logged_in = sqlm.check_if_user_logged_in(username)

            if logged_in:
                log.debug(
                    f"check_which_user_logged_in_for_mac_address: User {username} logged in at MAC address {mac_address}"
                )
                return username

    return None


def ensure_set_persistence():
    elem_dict = nftm.pull_elements_from_custom_sets(nftm.TABLE_FAMILY, nftm.TABLE_NAME)
    p = Path(sqlh.USAGE_TRACKING_DB_PATH).parent / "nft_persistence.pkl"
    with open(p, "wb") as file:
        pickle.dump(elem_dict, file)


def initialize_nftables_sets():
    p = Path(sqlh.USAGE_TRACKING_DB_PATH).parent / "nft_persistence.pkl"

    if p.exists():
        with open(p, "rb") as file:
            elem_dict = pickle.load(file)

        for key in elem_dict.keys():
            elems = elem_dict[key]

            for elem in elems:
                nftm.operation_on_set_element(
                    "add",
                    nftm.TABLE_FAMILY,
                    nftm.TABLE_NAME,
                    key,
                    elem["elem"]["val"],
                )
