import logging
import pickle
from python_arptable import get_arp_table
from pathlib import Path
import datetime as dt

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


def is_user_authenticated(username, user_ip):
    in_group = sqlm.check_if_user_in_any_group(
        username, db_path=sqlh.USAGE_TRACKING_DB_PATH
    )
    try:
        ip_in_set = nftm.check_if_elem_in_set(
            user_ip, nftm.TABLE_FAMILY, nftm.TABLE_NAME, nftm.AUTH_SET_NAME
        )
    except sqlh.IPAddressError:
        log.debug(f"IP address {user_ip} not in nft set.")
        return False
    logged_in = sqlm.check_if_user_logged_in(username)
    return in_group and ip_in_set and logged_in


def fetch_user_bytes(username):
    log.debug(f"Fetching user bytes for user {username}...")
    try:
        user_ip = sqlm.fetch_user_ip_address_usage(username)
    except sqlh.IPAddressError:
        log.debug(f"No IP address for user {username}.")
        return None

    try:
        user_bytes = nftm.get_bytes_from_user(user_ip)
    except nftm.NFTSetMissingElementError:
        log.debug(f"Authorized users set empty.")
        return None

    log.debug(f"User bytes: {user_bytes}")

    return user_bytes


def initialize_session_start_bytes(ip_addr):
    log.debug(f"Initializing session start bytes for user at {ip_addr}")
    try:
        session_start_bytes = nftm.get_bytes_from_user(ip_addr)
    except (nftm.NFTSetMissingElementError, sqlh.IPAddressError):
        log.debug(f"IP address {ip_addr} not in set.")
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


def reset_throttling_and_packet_dropping(
    username=None, db_path=sqlh.USAGE_TRACKING_DB_PATH
):

    if username is None:
        nftm.flush_set(nftm.TABLE_FAMILY, nftm.TABLE_NAME, nftm.THROTTLE_SET_NAME)
        nftm.flush_set(nftm.TABLE_FAMILY, nftm.TABLE_NAME, nftm.DROP_SET_NAME)

        usernames = sqlm.fetch_all_usernames_usage(db_path)
    else:
        usernames = [username]

    for username in usernames:

        try:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
        except sqlm.UserNameError:
            user_ip = None

        if user_ip is None:
            log.error(
                f"ERROR: failed to reset throttling for user {username}. User IP address not found."
            )
            raise sqlh.IPAddressError(f"No IP address found for user {username}")

        nftm.operation_on_set_element(
            "add",
            nftm.TABLE_FAMILY,
            nftm.TABLE_NAME,
            nftm.HIGH_SPEED_SET_NAME,
            user_ip,
        )

        log.info(f"Reset throttling and packet dropping for user: {username}")


def enforce_quotas_all_users(
    quota_dict, throttling: bool, db_path=sqlh.USAGE_TRACKING_DB_PATH
):

    usernames = sqlm.fetch_all_usernames_usage(db_path)

    for username in usernames:
        if sqlm.check_if_user_logged_in(username):
            if sqlm.check_if_daily_bytes_exceeds_high_speed_quota_for_user_usage(
                username, db_path
            ):
                if username not in quota_dict["over_quota"]:
                    quota_dict["over_quota"].append(username)

                    if username in quota_dict["under_quota"]:
                        quota_dict["under_quota"].remove(username)

                    try:
                        ip_addr = sqlm.fetch_user_ip_address_usage(username)
                    except sqlm.UserNameError:
                        log.error(
                            f"ERROR: failed to fetch IP addres for user {username}. User not found."
                        )
                        raise sqlm.UserNameError(
                            f"No IP address found for user {username}"
                        )

                    # Add error catching here

                    if throttling:
                        nftm.operation_on_set_element(
                            "add",
                            nftm.TABLE_FAMILY,
                            nftm.TABLE_NAME,
                            nftm.THROTTLE_SET_NAME,
                            ip_addr,
                        )
                        nftm.operation_on_set_element(
                            "delete",
                            nftm.TABLE_FAMILY,
                            nftm.TABLE_NAME,
                            nftm.HIGH_SPEED_SET_NAME,
                            ip_addr,
                        )
                        nftm.operation_on_set_element(
                            "delete",
                            nftm.TABLE_FAMILY,
                            nftm.TABLE_NAME,
                            nftm.DROP_SET_NAME,
                            ip_addr,
                        )
                        log.info(
                            f"Daily usage exceeds quota for user: {username}. Throttling to 1mbps..."
                        )
                    else:
                        nftm.operation_on_set_element(
                            "delete",
                            nftm.TABLE_FAMILY,
                            nftm.TABLE_NAME,
                            nftm.THROTTLE_SET_NAME,
                            ip_addr,
                        )
                        nftm.operation_on_set_element(
                            "delete",
                            nftm.TABLE_FAMILY,
                            nftm.TABLE_NAME,
                            nftm.HIGH_SPEED_SET_NAME,
                            ip_addr,
                        )
                        nftm.operation_on_set_element(
                            "add",
                            nftm.TABLE_FAMILY,
                            nftm.TABLE_NAME,
                            nftm.DROP_SET_NAME,
                            ip_addr,
                        )
                        log.info(
                            f"Daily usage exceeds quota for user: {username}. Dropping packets..."
                        )
            else:
                if username not in quota_dict["under_quota"]:
                    quota_dict["under_quota"].append(username)

                    if username in quota_dict["over_quota"]:
                        quota_dict["over_quota"].remove(username)

                    log.info(
                        f"Resetting throttling and packet dropping for: {username}..."
                    )

                    reset_throttling_and_packet_dropping(username)

    return quota_dict


def add_user_to_set(username, set_name, user_ip=None):

    if user_ip is None:
        try:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
        except sqlm.UserNameError:
            log.debug(f"User {username} does not exist.")
            user_ip = None

    if user_ip:
        nftm.operation_on_set_element(
            "add",
            nftm.TABLE_FAMILY,
            nftm.TABLE_NAME,
            set_name,
            user_ip,
        )
        log.debug(f"Added user {username} to set {set_name}.")
    else:
        log.error(f"Failed to add user {username} to set {set_name}")


def delete_user_from_set(username, set_name):
    try:
        user_ip = sqlm.fetch_user_ip_address_usage(username)
    except sqlm.UserNameError:
        log.debug(f"User {username} does not exist.")
        user_ip = None

    if user_ip is not None:
        nftm.operation_on_set_element(
            "delete",
            nftm.TABLE_FAMILY,
            nftm.TABLE_NAME,
            set_name,
            user_ip,
        )
        log.debug(f"Deleted user {username} from set {set_name}.")


def unauthorize_user(username):

    if sqlm.check_if_user_exists(username):
        delete_user_from_set(username, nftm.AUTH_SET_NAME)
        delete_user_from_set(username, nftm.HIGH_SPEED_SET_NAME)
        delete_user_from_set(username, nftm.THROTTLE_SET_NAME)
        delete_user_from_set(username, nftm.DROP_SET_NAME)
        log.info(f"Successfully unauthorized user {username}.")
    else:
        log.info(f"User {username} doesn't exist.")


def log_in_user(username, user_ip, user_mac):

    if sqlm.check_if_user_exists(username):
        try:

            old_username_for_ip_address = check_which_user_logged_in_for_ip_address(
                user_ip
            )

            if old_username_for_ip_address and (
                old_username_for_ip_address is not username
            ):
                log_out_user(old_username_for_ip_address)

            add_user_to_set(username, nftm.AUTH_SET_NAME, user_ip=user_ip)

            session_start_bytes = initialize_session_start_bytes(user_ip)

            sqlm.login_user_usage(username, user_mac, user_ip, session_start_bytes)

            sqlm.wipe_session_total_bytes(username)

        except Exception as e:
            log.error(f"Error logging in user: {username}: {e}")

            log_out_user(username)

            # For flask_server
            raise e

        return True
    else:
        raise sqlm.UserNameError(f"User {username} does not exist.")


def log_out_user(username):

    try:
        unauthorize_user(username)

        sqlm.wipe_session_total_bytes(username)

        sqlm.logout_user_usage(username)

        log.info(f"Successfully logged out user {username}.")

    except Exception as e:
        log.error(f"Error logging out user {username}: {e}")
        return False

    return True


def log_out_all_users():
    usernames = sqlm.fetch_all_usernames_usage()

    for username in usernames:
        log_out_user(username)


def delete_user_from_system(username):

    user_exists_usage = sqlm.check_if_user_exists(username)
    user_exists_radius = sqlm.check_if_user_exists(
        username, table_name="radcheck", db_path=sqlh.RADIUS_DB_PATH
    )

    if user_exists_usage:
        sqlm.delete_user_usage(username)

    if user_exists_radius:
        sqlm.delete_user_radius(username)

    unauthorize_user(username)

    log.info(f"Successfully deleted user {username} from system.")


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


def check_which_user_logged_in_for_ip_address(ip_addr):
    usernames = sqlm.get_usernames_from_ip_address_usage(ip_addr)

    if usernames is not None:
        for username in usernames:
            logged_in = sqlm.check_if_user_logged_in(username)

            if logged_in:
                log.debug(
                    f"check_which_user_logged_in_for_ip_address: User {username} logged in at IP address {ip_addr}"
                )
                return username

    return None


def ip_timeout_updater(ip_addr, mac_addr):
    if ip_addr is None:
        return None

    if check_which_user_logged_in_for_ip_address(ip_addr):

        tz = dt.timezone(dt.timedelta(hours=sqlh.UTC_OFFSET))
        now = dt.datetime.now(tz).timestamp()

        row = sqlm.select_ip_row(ip_addr)

        if row:

            log.debug(
                f"ip_timeout_updater: table information for user at {ip_addr}/{mac_addr}: {row}"
            )

            sqlm.update_ip_db(ip_addr, now, time_left_before_timeout=sqlm.IP_TIMEOUT)

            log.debug(f"Updated timeout for user {ip_addr}/{mac_addr}.")
        else:
            sqlm.insert_ip_addr_ip_db(ip_addr, mac_addr, now)
    else:
        if sqlm.check_if_value_in_table(
            ip_addr,
            "ip_addr",
            sqlm.IP_TIMEOUT_TABLE_NAME,
            sqlh.USAGE_TRACKING_DB_PATH,
        ):
            sqlm.delete_ip_neigh(ip_addr)


def ip_timeout_enforcer():

    tz = dt.timezone(dt.timedelta(hours=sqlh.UTC_OFFSET))
    now = dt.datetime.now(tz).timestamp()

    ip_and_mac_addrs = sqlm.fetch_all_ip_addr_ip_timeouts()

    log.debug(f"ip_timeout_enforcer: IP and MAC addrs in db: {ip_and_mac_addrs}")

    for ip_addr, mac_addr in ip_and_mac_addrs:
        row = sqlm.select_ip_row(ip_addr)

        last_timestamp = row[3]
        time_left_before_timeout = row[5]

        log.debug(
            f"ip_timeout_enforcer: table information for user at {ip_addr}: {row}"
        )

        if time_left_before_timeout <= 0:
            log.debug(f"ip_timeout_enforcer: Enforcing timeout for user at {ip_addr}")

            success = ip_enforce_timeout(ip_addr, mac_addr)

            # May need to add some else logic here in future if enforcement gets more complicated.
            if success:
                sqlm.delete_ip_neigh(ip_addr)
                log.debug(
                    f"ip_timeout_enforcer: Deleting user at {ip_addr} from ip_timeouts table"
                )
        else:
            new_time_left_before_timeout = int(
                time_left_before_timeout - (now - last_timestamp)
            )
            sqlm.update_ip_db(
                ip_addr, now, time_left_before_timeout=new_time_left_before_timeout
            )
            log.debug(f"ip_timeout_enforcer: Updated ip timeouts for user at {ip_addr}")


def ip_enforce_timeout(ip_addr, mac_addr):

    usernames = sqlm.get_usernames_from_ip_and_mac_usage(ip_addr, mac_addr)

    # If somehow there are multiple users logged in with the same MAC / IP combo,
    # log them all out...
    for username in usernames:
        success = log_out_user(username)

    # In future, maybe add to short DHCP lease pool.

    log.info(f"Timeout enforced for user at {ip_addr}")

    return success


def wipe_ip_neigh_db():
    sqlh.wipe_table(sqlm.IP_TIMEOUT_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH)
