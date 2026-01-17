import logging
import time

from python_arptable import get_arp_table
from pyroute2 import IPRoute
from pyroute2.netlink.rtnl.ndmsg import NUD_REACHABLE

from quota_manager import sql_management as sqlm
from quota_manager import nftables_management as nftm
from quota_manager import sqlite_helper_functions as sqlh

log = logging.getLogger(__name__)

ip = IPRoute()


def mac_from_ip(ip):
    arp_table = get_arp_table()
    mac_address = None
    for entry in arp_table:
        if entry["IP address"] == ip:
            mac_address = entry["HW address"]

    if mac_address is None:
        log.error(f"No MAC address found associated with ip {ip}.")
        raise sqlh.MACAddressError(f"No MAC address found associated with ip {ip}.")

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
        log.debug(f"High speed users set empty.")
        return None

    log.debug(f"User bytes: {user_bytes}")

    return user_bytes


def initialize_session_start_bytes(ip_addr):
    log.debug(f"Initializing session start bytes for user at {ip_addr}")
    if not nftm.check_if_user_dropped(ip_addr) or nftm.check_if_user_throttled(ip_addr):
        try:
            session_start_bytes = nftm.get_bytes_from_user(ip_addr)
        except (nftm.NFTSetMissingElementError, sqlh.IPAddressError):
            log.debug(f"IP address {ip_addr} not in set.")
            session_start_bytes = 0
        log.debug(f"Session start bytes: {session_start_bytes}")
        return session_start_bytes
    else:
        return 0


def initialize_user_state_nftables(username, throttling=False):

    exceeds_quota, _, _ = evaluate_user_bytes_against_quota(username)

    # All of these nftables functions are atomic, no worries
    if exceeds_quota:
        if throttling:
            log.debug(
                f"Recently logged in user {username} exceeds quota. Throttling..."
            )
            throttle_single_user(username)
        else:
            log.debug(
                f"Recently logged in user {username} exceeds quota. Dropping packets..."
            )
            drop_single_user(username)
    else:
        log.debug(
            f"Recently logged in user {username} under quota. Adding to high-speed users..."
        )
        make_single_user_high_speed(username)


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
        if not sqlm.check_if_user_exceeds_quota(username):
            usage_dict = update_user_bytes(username, usage_dict)

    return usage_dict


def throttle_single_user(username, user_ip=None):

    if user_ip is None:
        try:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
        except sqlm.UserNameError:
            log.debug(
                f"Failed to reset throttling for user {username}. User does not exist."
            )
            user_ip = None

    if user_ip:
        nftm.throttle_ip(user_ip)
        log.debug(f"User {username} throttled.")


def drop_single_user(username, user_ip=None):

    if user_ip is None:
        try:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
        except sqlm.UserNameError:
            log.debug(
                f"Failed to reset throttling for user {username}. User does not exist."
            )
            user_ip = None

    if user_ip:
        nftm.drop_ip(user_ip)
        log.debug(f"Packets from user {username} dropped.")


def make_single_user_high_speed(username, user_ip=None):

    if user_ip is None:
        try:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
        except sqlm.UserNameError:
            log.debug(
                f"Failed to make user {username} high speed. User does not exist."
            )
            user_ip = None
    if user_ip:
        if not nftm.check_if_user_high_speed(user_ip):
            add_user_to_set(username, nftm.HIGH_SPEED_SET_NAME, user_ip=user_ip)
            log.debug(f"User {username} made high-speed.")


def reset_throttling_single_user(username, user_ip=None):

    if user_ip is None:
        try:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
        except sqlm.UserNameError:
            log.debug(
                f"Failed to reset throttling for user {username}. User does not exist."
            )
            user_ip = None

    if user_ip:
        nftm.unthrottle_ip(user_ip)
        log.debug(f"User {username} unthrottled.")


def reset_dropping_single_user(username, user_ip=None):

    if user_ip is None:
        try:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
        except sqlm.UserNameError:
            log.debug(
                f"Failed to reset throttling for user {username}. User does not exist."
            )
            user_ip = None

    if user_ip:
        nftm.undrop_ip(user_ip)
        log.debug(f"User {username} undropped.")


def reset_throttling_and_packet_dropping_all_users(db_path=sqlh.USAGE_TRACKING_DB_PATH):

    nftm.flush_set(nftm.TABLE_FAMILY, nftm.TABLE_NAME, nftm.THROTTLE_SET_NAME)
    nftm.flush_set(nftm.TABLE_FAMILY, nftm.TABLE_NAME, nftm.DROP_SET_NAME)

    usernames = sqlm.fetch_all_usernames_usage(db_path)

    for username in usernames:

        try:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
        except sqlm.UserNameError:
            log.debug(
                f"Failed to reset throttling and packet_dropping for user {username}. User does not exist."
            )
            user_ip = None

        if user_ip:
            nftm.unthrottle_ip(user_ip)
            nftm.undrop_ip(user_ip)


def remove_user_from_nftables(username):

    if sqlm.check_if_user_exists(username):

        try:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
        except sqlh.IPAddressError:
            log.debug(f"No IP address for user {username}.")
            return None

        if user_ip is not None:
            nftm.operation_on_set_element(
                "delete",
                nftm.TABLE_FAMILY,
                nftm.TABLE_NAME,
                nftm.AUTH_SET_NAME,
                user_ip,
            )

            nftm.operation_on_set_element(
                "delete",
                nftm.TABLE_FAMILY,
                nftm.TABLE_NAME,
                nftm.DROP_SET_NAME,
                user_ip,
            )

            nftm.operation_on_set_element(
                "delete",
                nftm.TABLE_FAMILY,
                nftm.TABLE_NAME,
                nftm.THROTTLE_SET_NAME,
                user_ip,
            )

            nftm.operation_on_set_element(
                "delete",
                nftm.TABLE_FAMILY,
                nftm.TABLE_NAME,
                nftm.HIGH_SPEED_SET_NAME,
                user_ip,
            )

    else:
        log.info(f"User {username} doesn't exist.")


def get_quota_and_daily_usage(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):

    quota_bytes = sqlm.fetch_high_speed_quota_for_user_usage(username, db_path)
    daily_usage_bytes = sqlm.fetch_daily_bytes_usage(username, db_path)

    return daily_usage_bytes, quota_bytes


def evaluate_quota(usage_bytes, quota_bytes):

    if quota_bytes is None:
        return False  # or False with a clear reason — but choose explicitly

    if usage_bytes >= quota_bytes:
        return True

    return False


def evaluate_user_bytes_against_quota(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):

    try:
        daily_usage_bytes, quota_bytes = get_quota_and_daily_usage(username, db_path)
    except sqlm.UserNameError as e:
        raise sqlm.UserNameError(
            f"Operation to fetch daily usage bytes for user {username} failed: {e}"
        )

    exceeds_quota = evaluate_quota(daily_usage_bytes, quota_bytes)

    return exceeds_quota, daily_usage_bytes, quota_bytes


def update_quota_information_single_user(username, db_path=sqlh.USAGE_TRACKING_DB_PATH):

    if sqlm.check_if_user_logged_in(username):

        exceeds_quota, daily_usage_bytes, quota_bytes = (
            evaluate_user_bytes_against_quota(username, db_path)
        )

        if exceeds_quota != sqlm.check_if_user_exceeds_quota(username, db_path):
            sqlm.update_user_quota_information(username, exceeds_quota, db_path)
            log.debug(
                f"Quota state has changed, updating quota information for user {username}..."
            )

        return exceeds_quota, daily_usage_bytes, quota_bytes
    return None, None, None


def update_quota_information_all_users(quota_dict, db_path=sqlh.USAGE_TRACKING_DB_PATH):
    usernames = sqlm.fetch_all_usernames_usage(db_path)

    for username in usernames:

        if username not in quota_dict:
            quota_dict[username] = {"exceeds_quota": False, "quota_msg": ""}

        exceeds_quota, daily_usage_bytes, quota_bytes = (
            update_quota_information_single_user(username, db_path)
        )

        if exceeds_quota and daily_usage_bytes and quota_bytes:
            quota_dict[username]["exceeds_quota"] = exceeds_quota
            quota_dict[username]["quota_msg"] = f"{daily_usage_bytes}/{quota_bytes}"

    return quota_dict


def enforce_quota_single_user(
    username, throttling: bool, db_path=sqlh.USAGE_TRACKING_DB_PATH
):

    if sqlm.check_if_user_logged_in(username):

        user_exceeds_quota = sqlm.check_if_user_exceeds_quota(username, db_path)

        try:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
        except sqlm.UserNameError:
            log.debug(f"User {username} does not exist.")
            user_ip = None

        user_throttled = nftm.check_if_user_throttled(user_ip)
        user_dropped = nftm.check_if_user_dropped(user_ip)

        if user_exceeds_quota:

            # Add error catching here.

            if throttling:
                if not user_throttled:
                    throttle_single_user(username, user_ip=user_ip)
                    log.info(f"Throttling {username} to 1mbps...")

            else:
                if not user_dropped:
                    drop_single_user(username, user_ip=user_ip)
                    log.info(f"Dropping packets from {username}...")

        else:

            if user_throttled:
                reset_throttling_single_user(username, user_ip=user_ip)
                log.info(f"Reset throttling for user {username}.")
            elif user_dropped:
                reset_dropping_single_user(username, user_ip=user_ip)
                log.info(f"Reset packet dropping for user {username}.")
            else:
                make_single_user_high_speed(username, user_ip=user_ip)


def enforce_quotas_all_users(throttling: bool, db_path=sqlh.USAGE_TRACKING_DB_PATH):

    usernames = sqlm.fetch_all_usernames_usage(db_path)

    for username in usernames:

        enforce_quota_single_user(username, throttling, db_path)


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


def nft_authorize_user(username):

    if sqlm.check_if_user_exists(username):

        try:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
        except sqlh.IPAddressError:
            log.debug(f"No IP address for user {username}.")
            return None

        nftm.auth_ip(user_ip)
        log.debug(f"Added user {username} to {nftm.AUTH_SET_NAME} set.")

    else:
        log.info(f"User {username} doesn't exist.")


def unauthorize_user(username):

    if sqlm.check_if_user_exists(username):

        try:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
        except sqlh.IPAddressError:
            log.debug(f"No IP address for user {username}.")
            return None

        nftm.unauth_ip(user_ip)

    else:
        log.info(f"User {username} doesn't exist.")


def log_in_user(username, user_ip, user_mac):

    if sqlm.check_if_user_exists(username):
        try:
            old_usernames_for_ip_address = check_which_users_logged_in_for_ip_address(
                user_ip
            )
            if old_usernames_for_ip_address:
                log.debug(
                    f"Multiple users detected for IP {user_ip}: {old_usernames_for_ip_address}. Logging out users..."
                )
                for old_username in old_usernames_for_ip_address:
                    if old_username and (old_username != username):
                        log_out_user(old_username)

            # Place the user in the set they belong in (high-speed, throttled, dropped)
            initialize_user_state_nftables(username)

            # Place user in authorized_users set.
            nft_authorize_user(username)

            session_start_bytes = initialize_session_start_bytes(user_ip)

            # Update users database
            sqlm.login_user_usage(username, user_mac, user_ip, session_start_bytes)

            sqlm.wipe_session_total_bytes(username)

            # Initialize ip timeouts
            now = time.monotonic()
            ip_timeout_updater(user_ip, user_mac, now, first_pass=True)

        except Exception as e:
            log.error(f"Error logging in user: {username}: {e}")

            log_out_user(username)

            # For flask_server
            raise e

        return True
    else:
        raise sqlm.UserNameError(f"User {username} does not exist.")


def log_out_user(username):

    if sqlm.check_if_user_logged_in(username):
        try:
            remove_user_from_nftables(username)

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

    remove_user_from_nftables(username)

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


def check_which_users_logged_in_for_ip_address(ip_addr):
    usernames = sqlm.get_usernames_from_ip_address_usage(ip_addr)

    logged_in_users = []
    if usernames is not None:
        for username in usernames:
            logged_in = sqlm.check_if_user_logged_in(username)

            if logged_in:
                log.debug(
                    f"check_which_users_logged_in_for_ip_address: User {username} logged in at IP address {ip_addr}"
                )
                logged_in_users.append(username)

    if logged_in_users:
        return logged_in_users
    return None


# ----- Beginning IP Neigh Utility Functions ----- #


def poll_ip_neigh():
    now = time.monotonic()
    neighbors = ip.get_neighbours()

    for n in neighbors:
        try:
            if n["state"] & NUD_REACHABLE:
                ip_addr = dict(n.get("attrs")).get("NDA_DST")
                mac_addr = dict(n.get("attrs")).get("NDA_LLADDR")
                return ip_addr, mac_addr, now
        except Exception as e:
            log.error(f"Unexpected error updating ip timeout database for {n}: {e}.")

    return None, None, None


def ip_timeout_updater(ip_addr, mac_addr, now, first_pass=False):
    if ip_addr is None:
        return None

    if check_which_users_logged_in_for_ip_address(ip_addr):

        row = sqlm.select_ip_row(ip_addr)

        if row:

            log.debug(
                f"ip_timeout_updater: table information for user at {ip_addr}/{mac_addr}: {row}"
            )

            last_timestamp = row[3]

            ip_timeout = sqlm.IP_TIMEOUT * 3 if first_pass else sqlm.IP_TIMEOUT

            timeout = 1 if now - last_timestamp > ip_timeout else 0

            sqlm.update_ip_db(ip_addr, now, timeout)

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

    ip_and_mac_addrs = sqlm.fetch_all_ip_addr_ip_timeouts()

    log.debug(f"ip_timeout_enforcer: IP and MAC addrs in db: {ip_and_mac_addrs}")

    for ip_addr, mac_addr in ip_and_mac_addrs:
        row = sqlm.select_ip_row(ip_addr)

        timeout = row[4]

        log.debug(
            f"ip_timeout_enforcer: table information for user at {ip_addr}: {row}"
        )

        if timeout:

            success = ip_enforce_timeout(ip_addr, mac_addr)

            # May need to add some else logic here in future if enforcement gets more complicated.
            if success:
                log.debug(
                    f"ip_timeout_enforcer: Enforced timeout for user at {ip_addr}"
                )
                sqlm.delete_ip_neigh(ip_addr)
                log.debug(
                    f"ip_timeout_enforcer: Deleting user at {ip_addr} from ip_timeouts table"
                )
            else:
                log.error(
                    f"ip_timeout_enforcer: ERROR: Failed to enforce timeout for user at {ip_addr}"
                )


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
