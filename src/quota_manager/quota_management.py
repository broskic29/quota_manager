import logging
import time
import datetime as dt

try:
    from python_arptable import get_arp_table
except (ImportError, FileNotFoundError):
    get_arp_table = None

try:
    from pyroute2 import IPRoute
    from pyroute2.netlink.rtnl.ndmsg import NUD_REACHABLE
except (ImportError, FileNotFoundError):
    IPRoute = None
    NUD_REACHABLE = None

from math import fsum

from quota_manager import sql_management as sqlm
from quota_manager import nftables_management as nftm
from quota_manager import sqlite_helper_functions as sqlh

from quota_manager.quota_tools import smart_quota_tool as sqt

log = logging.getLogger(__name__)

ip = IPRoute() if IPRoute is not None else None

ACCOUNT_BILLING_DAY = 7

# Add a lock to prevent race conditions in usage updater
import threading

RESET_LOCK = threading.RLock()
QUOTA_LOCK = threading.RLock()

QUOTAS_DIRTY = threading.Event()

from collections import defaultdict

USER_LOCKS = defaultdict(threading.RLock)


class RestrictedDayError(Exception):
    """Raised when an action is attempted on a restricted day."""

    pass


class RestrictedUserError(Exception):
    """Raised when an restricted user attempts to log in."""

    pass


class QuotaAllottmentError(Exception):
    """Impossible to calculate quota for user with current constraints. Please change desired quota ratio for group."""

    pass


def mac_from_ip(ip):
    if get_arp_table is None:
        raise RuntimeError("python_arptable not installed (mac_from_ip unavailable)")

    arp_table = get_arp_table()
    mac_address = None
    if arp_table:
        for entry in arp_table:
            if entry["IP address"] == ip:
                mac_address = entry["HW address"]

    if mac_address is None:
        log.error(f"No MAC address found associated with ip {ip}.")
        raise sqlh.MACAddressError(f"No MAC address found associated with ip {ip}.")

    return mac_address


def fetch_user_ip(username):
    try:
        user_ip = sqlm.fetch_user_ip_address_usage(username)
    except sqlm.UserNameError:
        log.debug(f"User {username} does not exist.")
        user_ip = None

    return user_ip


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
    # log.debug(f"Fetching user bytes for user {username}...")
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
    except sqlh.IPAddressError as e:
        log.debug(f"fetch_user_bytes: User {username} ip address not in set {e}.")
        log_out_user(username)
        return None

    # log.debug(f"User bytes: {user_bytes}")

    return user_bytes


def initialize_session_start_bytes(ip_addr):
    log.debug(f"Initializing session start bytes for user at {ip_addr}")
    try:
        session_start_bytes = nftm.get_bytes_from_user(ip_addr)
    except (nftm.NFTSetMissingElementError, sqlh.IPAddressError):
        log.debug(f"IP address {ip_addr} not in set.")
        session_start_bytes = 0
    log.debug(f"Session start bytes: {session_start_bytes}")
    return session_start_bytes


def initialize_session_start_bytes_for_system(system_name):
    log.debug(f"Initializing session start bytes for system '{system_name}'")
    try:
        system_session_start_bytes = nftm.get_system_bytes_subprocess(
            nftm.TABLE_FAMILY,
            nftm.TABLE_NAME,
            nftm.QUOTA_MANAGER_FORWARD_CHAIN_NAME,
            nftm.WAN_IFACE_NAME,
        )
    except Exception as e:
        log.error(f"Failed to initialize start bytes for system: {e}")
        system_session_start_bytes = 0
    log.debug(f"Session start bytes: {system_session_start_bytes}")

    sqlm.update_session_start_bytes(system_session_start_bytes, system_name=system_name)


def initialize_user_state_nftables(username, throttling=False):

    exceeds_quota, _, _ = evaluate_user_bytes_against_quota(username)

    config = sqlm.fetch_active_config()

    # All of these nftables functions are atomic, no worries
    if config:
        if exceeds_quota:
            if config["throttling_enabled"]:
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
    else:
        log.error(
            "initialize_user_state_nftables: Failed to initialize user state for nftables. No active config."
        )
        raise sqlm.ConfigNameError(
            "initialize_user_state_nftables: Failed to initialize user state for nftables. No active config."
        )


def calculate_byte_delta(user_bytes, username=None, system_name=None, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    session_total_bytes = sqlm.fetch_session_bytes(
        username=username, system_name=system_name, byte_type="total", db_path=db_path
    )
    session_start_bytes = sqlm.fetch_session_bytes(
        username=username, system_name=system_name, byte_type="start", db_path=db_path
    )

    # nft counter reset / rollover / element re-added
    if user_bytes < session_start_bytes:
        log.warning(
            f"Counter reset detected for {username}: user_bytes={user_bytes} < session_start_bytes={session_start_bytes}. "
            "Resetting session tracking baseline."
        )
        sqlm.update_session_start_bytes(
            user_bytes, username=username, system_name=system_name, db_path=db_path
        )
        sqlm.wipe_session_total_bytes(
            username=username, system_name=system_name, db_path=db_path
        )
        return 0

    byte_delta = (user_bytes - session_start_bytes) - session_total_bytes
    if byte_delta < 0:
        # defensive: should not happen, but never subtract usage
        if username:
            log.warning(
                f"Negative byte delta for user {username}: {byte_delta}. Reeintializing session start bytes and total session bytes."
            )
            sqlm.update_session_start_bytes(
                user_bytes, username=username, db_path=db_path
            )
            sqlm.wipe_session_total_bytes(username=username)
        else:

            config = sqlm.fetch_active_config()

            if config is None:
                log.error(
                    f"calculate_byte_delta: Table {sqlm.CONFIGS_TABLE_NAME} empty or does not exist."
                )
                log.warning(
                    f"Negative byte delta for system: {byte_delta}. Reeintializing session start bytes and total session bytes."
                )

                sqlm.update_session_start_bytes(
                    user_bytes, system_name=system_name, db_path=db_path
                )
                sqlm.wipe_session_total_bytes(system_name=system_name)

                return 0
            system_name = config["system_name"]

            log.warning(
                f"Negative byte delta for system '{system_name}': {byte_delta}. Clamping to 0."
            )

            sqlm.update_session_start_bytes(
                user_bytes, system_name=system_name, db_path=db_path
            )
            sqlm.wipe_session_total_bytes(system_name=system_name)
        return 0

    return byte_delta


def calculate_hypothetical_group_quotas_for_today(
    now=None, group_name=None, reset_day=ACCOUNT_BILLING_DAY, old_group_name=None
):

    with QUOTA_LOCK:

        total_monthly_bytes_purchased = sqlm.fetch_config_total_bytes()
        total_monthly_bytes_used = sqlm.fetch_total_system_monthly_usage_bytes()

        if total_monthly_bytes_used is None:
            return

        total_monthly_bytes_available = max(
            total_monthly_bytes_purchased - total_monthly_bytes_used, 0
        )

        if total_monthly_bytes_purchased is None or total_monthly_bytes_used is None:
            log.debug(
                f"update_group_quotas: Failed to update group quotas, total_monthly_bytes_purchased and/or total_bytes_used are empty."
            )
            raise QuotaAllottmentError(
                "update_group_quotas: Failed to update group quotas, total_monthly_bytes_purchased and/or total_bytes_used are empty. Please check configuration."
            )

        if now is None:
            tz = dt.timezone(dt.timedelta(hours=sqlh.UTC_OFFSET))
            now = dt.datetime.now(tz)

        total_weekdays_left = compute_remaining_weekdays(now, reset_day)

        total_usage_today = sqlm.fetch_daily_system_bytes()

        total_daily_bytes = max(
            ((total_monthly_bytes_available / total_weekdays_left) - total_usage_today),
            0,
        )

        group_config_dict = gen_group_config_dict_for_sqt(
            total_daily_bytes,
            user_group_name=group_name,
            old_user_group_name=old_group_name,
        )

        if not group_config_dict:
            log.info(
                "calculate_hypothetical_group_quotas_for_today: No active groups; skipping quota recompute."
            )
            return

        quota_config_dict = sqt.gen_quota_config_dict(
            total_daily_bytes, group_config_dict
        )
        log.debug(f"Quota config dict: {quota_config_dict}")

        try:
            group_quotas_dict = sqt.quota_vector_generator(quota_config_dict)["v_dict"]
            log.info(f"New data quotas: {group_quotas_dict}")
        except sqt.QuotaConfigError as e:
            log.debug(
                f"calculate_hypothetical_group_quotas_for_today: Failed to generate quotas dict: {e}"
            )
            raise sqt.QuotaConfigError(f"Failed to generate quotas dict: {e}")

        if group_quotas_dict is None:
            log.error(
                "Impossible to calculate group quotas with current constraints. Please change desired quota ratios."
            )
            raise sqt.QuotaConfigError(
                "Impossible to calculate group quotas with current constraints. Please change desired quota ratios."
            )

        return group_quotas_dict


def calculate_total_daily_usage():

    usernames = sqlm.fetch_all_usernames_usage()

    total_daily_usage = 0

    if usernames:
        for username in usernames:
            total_daily_usage += sqlm.fetch_daily_bytes_usage(username)

    return total_daily_usage


def update_user_bytes(username, usage_dict={}, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    if sqlm.check_if_user_logged_in(username):
        user_bytes = fetch_user_bytes(username)
        if user_bytes is not None:
            byte_delta = calculate_byte_delta(user_bytes, username)
            sqlm.update_user_bytes_usage(byte_delta, username, db_path)
            usage_dict[username] = user_bytes
    else:
        pass

    return usage_dict


def update_all_users_bytes(old_usage_dict, db_path=sqlh.USAGE_TRACKING_DB_PATH):

    usage_dict = {}
    usernames = sqlm.fetch_all_usernames_usage(db_path)

    if usernames:
        for username in usernames:
            if not sqlm.check_if_user_exceeds_quota(username):
                usage_dict = update_user_bytes(username, usage_dict)

    if usage_dict:
        # log.debug(usage_dict)
        return usage_dict

    return old_usage_dict


def update_total_system_bytes(db_path=sqlh.USAGE_TRACKING_DB_PATH):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    system_bytes = nftm.get_system_bytes_subprocess(
        nftm.TABLE_FAMILY,
        nftm.TABLE_NAME,
        nftm.QUOTA_MANAGER_FORWARD_CHAIN_NAME,
        nftm.WAN_IFACE_NAME,
    )

    log.debug(f"update_total_system_bytes: system_bytes: {system_bytes}")

    config = sqlm.fetch_active_config()

    if config is None:
        log.warning("update_total_system_bytes: System config not loaded.")
        return

    system_name = config["system_name"]

    if system_bytes is not None:
        byte_delta = calculate_byte_delta(system_bytes, system_name=system_name)
        sqlm.update_system_bytes_usage(byte_delta, system_name, db_path)
        sqlm.update_user_bytes_usage


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

            initialize_session_start_bytes(user_ip)
            log.debug(f"User {username} session bytes reinitialized.")

            sqlm.wipe_session_total_bytes(username=username)
            log.debug(f"Session total bytes for {username} wiped.")


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

        initialize_session_start_bytes(user_ip)
        log.debug(f"User {username} session bytes reinitialized.")

        sqlm.wipe_session_total_bytes(username=username)
        log.debug(f"Session total bytes for {username} wiped.")


def reset_throttling_and_packet_dropping_all_users(db_path=None):

    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    nftm.flush_set(nftm.TABLE_FAMILY, nftm.TABLE_NAME, nftm.THROTTLE_SET_NAME)
    nftm.flush_set(nftm.TABLE_FAMILY, nftm.TABLE_NAME, nftm.DROP_SET_NAME)

    usernames = sqlm.fetch_all_usernames_usage(db_path)

    if usernames:
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

        log.info("Throttling and packet dropping reset.")


def remove_user_from_nftables(username=None, user_ip=None):

    with USER_LOCKS[username]:

        if user_ip is None:
            if username is None:
                raise sqlh.IPAddressError(
                    f"Failure attempting to remove user from IP timeout database. IP Address not given and not associated with any user."
                )
            else:
                if sqlm.check_if_user_exists(username):
                    user_ip = fetch_user_ip(username)
                else:
                    log.info(f"User {username} doesn't exist.")

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


def remove_user_from_ip_timeouts(username=None, ip_addr=None):

    with USER_LOCKS[username]:

        if ip_addr is None:
            if username:
                ip_addr = fetch_user_ip(username)
                sqlm.delete_ip_neigh(ip_addr)
            else:
                raise sqlh.IPAddressError(
                    f"Failure attempting to remove user from IP timeout database. IP Address not given and not associated with any user."
                )

        sqlm.delete_ip_neigh(ip_addr)

        log.debug(f"Removed user {username} at {ip_addr} from timeouts table.")


def get_quota_and_daily_usage(username, db_path=None):

    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    quota_bytes = sqlm.fetch_high_speed_quota_for_user_usage(username, db_path)
    daily_usage_bytes = sqlm.fetch_daily_bytes_usage(username, db_path)

    return daily_usage_bytes, quota_bytes


def evaluate_quota(usage_bytes, quota_bytes):

    if quota_bytes is None:
        return False  # or False with a clear reason — but choose explicitly

    if usage_bytes >= quota_bytes:
        return True

    return False


def evaluate_user_bytes_against_quota(username, db_path=None):

    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    try:
        daily_usage_bytes, quota_bytes = get_quota_and_daily_usage(username, db_path)
    except sqlm.UserNameError as e:
        raise sqlm.UserNameError(
            f"Operation to fetch daily usage bytes for user {username} failed: {e}"
        )

    exceeds_quota = evaluate_quota(daily_usage_bytes, quota_bytes)

    return exceeds_quota, daily_usage_bytes, quota_bytes


def update_quota_information_single_user(username, db_path=None):

    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

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


def update_quota_information_all_users(quota_dict, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH

    usernames = sqlm.fetch_all_usernames_usage(db_path)

    if usernames:
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
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    if sqlm.check_if_user_logged_in(username):

        user_exceeds_quota = sqlm.check_if_user_exceeds_quota(username, db_path)

        user_ip = fetch_user_ip(username)

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


def enforce_quotas_all_users(throttling: bool, db_path=None):
    db_path = db_path or sqlh.USAGE_TRACKING_DB_PATH
    usernames = sqlm.fetch_all_usernames_usage(db_path)

    if usernames:
        for username in usernames:

            enforce_quota_single_user(username, throttling, db_path)


def update_num_entities_system_state(num_users, num_groups):
    usernames = sqlm.fetch_all_usernames_usage()
    groups = sqlm.get_groups_usage()

    if usernames is not None:
        new_num_users = len(usernames)
        if new_num_users != num_users:
            log.debug("Updating num_users...")
            sqlm.update_system_state_usage(num_users=new_num_users)
            num_users = new_num_users

    if groups is not None:
        new_num_groups = len(groups)
        if new_num_groups != num_groups:
            log.debug("Updating num_groups...")
            sqlm.update_system_state_usage(num_groups=new_num_groups)
            num_groups = new_num_groups

    return num_users, num_groups


def append_quotas_to_users_dicts(users):
    for user in users:
        username = user["username"]
        user_daily_quota = sqlm.fetch_high_speed_quota_for_user_usage(username)
        user["daily_quota_mib"] = user_daily_quota / 1024**2
    return users


def compute_remaining_weekdays(now, reset_day):
    """Count weekdays (Mon–Fri) remaining *after* the given day in the same month."""
    tz = now.tzinfo
    zero_hour = dt.datetime(now.year, now.month, now.day, tzinfo=tz)

    if now.day < reset_day:
        next_monthly = zero_hour.replace(day=reset_day)
    else:
        next_monthly = now + dt.timedelta(days=(32 - now.day))
        next_monthly = next_monthly.replace(day=reset_day)

    config = sqlm.fetch_active_config()

    cur = now  # start today
    count = 0
    while cur < next_monthly:
        if cur.weekday() in config["active_days_list"]:  # 0=Mon ... 4=Fri
            count += 1
        cur += dt.timedelta(days=1)
    return max(count, 1)


def calculate_next_monthly_reset(now, reset_day):
    """Count weekdays (Mon–Fri) remaining *after* the given day in the same month."""

    if now.day <= reset_day:
        next_monthly = now.replace(day=reset_day)
    else:
        next_monthly = now + dt.timedelta(days=(32 - now.day))
        next_monthly = next_monthly.replace(day=reset_day)
    return next_monthly


def calculate_max_num_bytes(group_config_dict, total_daily_bytes: float, *, tol=1e-3):
    active = {name: g for name, g in group_config_dict.items() if g.get("n", 0) > 0}
    if not active:
        log.debug(
            "calculate_max_num_bytes: Failed to calculate max num bytes. No active groups (all n=0)."
        )
        return group_config_dict

    denom = fsum(g["n"] * g["desired_quota_ratio"] for g in active.values())
    if denom <= tol:
        raise ValueError("Sum(n_i * desired_quota_ratio_i) must be > 0.")

    k = total_daily_bytes / denom

    for name, g in active.items():
        g["max_num_bytes"] = k * g["desired_quota_ratio"]

    return group_config_dict


def gen_group_config_dict_for_sqt(
    total_daily_bytes_available,
    user_group_name=None,
    old_user_group_name=None,
    tol=1e-6,
):
    group_config_dict = {}

    group_info = sqlm.fetch_group_quota_info_usage()

    if group_info is None:
        log.debug(
            "gen_group_config_dict_for_sqt: Failed to fetch group quota info, tables empty."
        )
        return

    for (
        group_name,
        num_members,
        desired_quota_ratio,
        min_quota_ratio,
        _,
        min_num_bytes,
        mse_weights,
    ) in group_info:
        group_config_dict[group_name] = {
            "n": num_members,
            "desired_quota_ratio": desired_quota_ratio,
            "min_quota_ratio": min_quota_ratio,
            "max_num_bytes": None,
            "min_num_bytes": min_num_bytes,
            "mse_weights": mse_weights,
        }

    # Increment number of users in the group if user_group_name is given!
    # Should make this behavior more exlicit. Passing user_group_name is changing function...
    if user_group_name:
        group_config_dict[user_group_name]["n"] += 1

    if old_user_group_name:
        group_config_dict[old_user_group_name]["n"] -= 1

    # after building group_config_dict from DB
    if all(g["n"] <= 0 for g in group_config_dict.values()):
        return None

    # Also some hidden behavior here. If n<= 0, max not incremented.
    group_config_dict = calculate_max_num_bytes(
        group_config_dict, total_daily_bytes_available
    )

    # log.debug(
    #     f"gen_group_config_dict_for_sqt: group_config_dict after max calcuation: {group_config_dict}"
    # )

    # cases
    # 1. No groups with any members - working!
    # 2. 1 group with members - not working...
    # 3. > 1 group with members
    # 4. all groups with members
    truncated_group_config_dict = {
        group_name: group_dict
        for group_name, group_dict in group_config_dict.items()
        if group_dict["n"] > 0
    }

    # log.debug(
    #     f"gen_group_config_dict_for_sqt: truncated_group_config_dict: {truncated_group_config_dict}"
    # )

    # Setting n=0 here because n is incremented in the calling function
    # `calculate_hypothetical_user_quota_for_tomorrow`.
    # Probably not the best solution, but should work fine, since this
    # group_config_dict creation only happens if there is a user_group_name
    # passed to the function, which only happens in
    # calculate_hypothetical_user_quota_for_tomorrow`
    if not truncated_group_config_dict:
        if user_group_name:
            group_config_dict = {
                user_group_name: {
                    "n": 0,
                    "desired_quota_ratio": 1.0,
                    "min_quota_ratio": 0.0,
                    "max_num_bytes": total_daily_bytes_available,
                    "min_num_bytes": 0.0,
                    "mse_weights": None,
                }
            }
            # Case where the first user in the system is being generated.
            return group_config_dict
        else:
            # Return None in case no groups and not being used to assign a new user.
            return None

    ratios = [
        group["desired_quota_ratio"]
        for group in truncated_group_config_dict.values()
        if group["n"] > 0
    ]

    # log.debug(f"gen_group_config_dict_for_sqt: ratios: {ratios}")
    # log.debug(f"gen_group_config_dict_for_sqt: group_config_dict: {group_config_dict}")

    total_ratio = fsum(ratios)
    leftover_ratio = 1.0 - total_ratio

    if abs(leftover_ratio) > tol:
        ratios = [ratio + leftover_ratio * (ratio / total_ratio) for ratio in ratios]
        ratios[-1] = 1.0 - fsum(ratios[:-1])

        for idx, (group_name, group_dict) in enumerate(
            truncated_group_config_dict.items()
        ):
            group_dict["desired_quota_ratio"] = ratios[idx]

    for group_name, group_dict in group_config_dict.items():
        if group_name in truncated_group_config_dict:
            group_config_dict[group_name] = truncated_group_config_dict[group_name]
        else:
            group_config_dict[group_name] = {
                "n": 0,
                "desired_quota_ratio": 0,
                "min_quota_ratio": 0,
                "max_num_bytes": 0,
                "min_num_bytes": 0,
                "mse_weights": None,
            }

    return group_config_dict


def apply_new_quotas(group_quotas_dict):
    with QUOTA_LOCK:
        if group_quotas_dict is not None:
            for group_name, quota_byte_value in group_quotas_dict.items():
                sqlm.update_group_quota(group_name, int(quota_byte_value))

            log.info(f"Updated daily quotas for all groups.")

            log.debug(f"New user quotas applied:")
            sqlh.log_all_table_information(sqlm.GROUP_TABLE_NAME)


def add_user_to_set(username, set_name, user_ip=None):

    if user_ip is None:
        user_ip = fetch_user_ip(username)

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
    with USER_LOCKS[username]:
        user_ip = fetch_user_ip(username)

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


def create_user(username, radius_password, group_name):

    with QUOTA_LOCK, USER_LOCKS[username]:

        user_exists = sqlm.check_if_user_exists(username)

        if user_exists:
            raise sqlm.UserNameError(
                f"Failed to create user {username}: User already exists."
            )

        tz = dt.timezone(dt.timedelta(hours=sqlh.UTC_OFFSET))
        now = dt.datetime.now(tz)

        # ---- Just prohibiting the super specific edge case where a user is created
        # at the same instant where daily usage is supposed to wipe
        if now.hour < 1 and now.min < 1:
            raise RuntimeError("User creation now allowed before 00:01.")

        sqlm.insert_user_radius(username, radius_password)
        log.debug(f"Inserted user {username} into radius db.")

        # Change to set up temporary quota, then disable whenever quota update is called.
        sqlm.create_user_usage(username, group_name)
        log.debug(f"Inserted user {username} into usage db.")


def change_user_group(username, new_group_name, old_group_name):

    with QUOTA_LOCK, USER_LOCKS[username]:

        user_exists = sqlm.check_if_user_exists(username)

        if not user_exists:
            raise sqlm.UserNameError(
                f"Failed to add user {username} to group {new_group_name}: User does not exist."
            )

        group_exists = sqlm.check_if_group_exists(new_group_name)

        if not group_exists:
            raise sqlm.GroupNameError(
                f"Failed to add user {username} to group {new_group_name}: Group does not exist."
            )

        sqlm.remove_user_from_group_usage(username)
        log.debug(f"Removed user {username} from group {old_group_name}.")

        sqlm.insert_user_into_group_usage(new_group_name, username)
        log.debug(f"Inserted user {username} into group {new_group_name}.")


def log_in_user(username, user_ip, user_mac):

    with USER_LOCKS[username]:

        config = sqlm.fetch_active_config()

        if config is None:
            raise sqlm.ConfigNameError(
                "log_in_user: Failed to log in user: No active configuration. "
            )

        tz = dt.timezone(dt.timedelta(hours=sqlh.UTC_OFFSET))
        now = dt.datetime.now(tz)

        if now.weekday() not in config["active_days_list"]:
            raise RestrictedDayError("Login not allowed on restricted days.")

        if config["mac_set_limitation"]:
            if user_mac not in config["allowed_macs_list"]:
                log.debug(
                    f"qm.log_in_user: User mac not in allowed macs list. User mac: {user_mac}"
                )
                log.debug(
                    f"qm.log_in_user: allowed_macs_list: {config['allowed_macs_list']}"
                )
                raise RestrictedUserError("User device not in list of allowed devices.")

        if sqlm.check_if_user_exists(username):

            # Make sure that switching devices for a logged in user is handled
            # properly...
            if sqlm.check_if_user_logged_in(username):
                old_user_ip = fetch_user_ip(username)
                if old_user_ip != user_ip:
                    log.debug(
                        f"New device detected for {username}. Clearing old IP address from system..."
                    )
                    remove_user_from_nftables(old_user_ip)

            # Clean up old IP addresses associated with a user
            try:
                users_logged_in_for_ip_addr, users_logged_out_for_ip_addr = (
                    check_which_users_logged_in_for_ip_address(user_ip)
                )

                if users_logged_in_for_ip_addr:
                    log.debug(
                        f"Multiple users detected for IP {user_ip}: logged in:{users_logged_in_for_ip_addr}, logged_out: {users_logged_out_for_ip_addr}. Logging out users..."
                    )
                    for old_username in users_logged_in_for_ip_addr:
                        log_out_user(old_username)

                if users_logged_out_for_ip_addr:
                    log.debug(
                        f"Multiple users detected for IP {user_ip}: logged in:{users_logged_in_for_ip_addr}, logged_out: {users_logged_out_for_ip_addr}. Wiping user from nft..."
                    )
                    for old_username in users_logged_out_for_ip_addr:
                        old_user_ip = sqlm.fetch_user_ip_address_usage(old_username)
                        remove_user_from_nftables(old_username, old_user_ip)

                # Update ip, mac, logged_in status
                sqlm.login_user_usage(username, user_mac, user_ip)

                # Add user to authorized users set
                nft_authorize_user(username)

                # Put user ip in correct nft set
                initialize_user_state_nftables(username)

                # Fetch start bytes from nft set
                session_start_bytes = initialize_session_start_bytes(user_ip)

                # Update db with start bytes
                sqlm.update_session_start_bytes(
                    session_start_bytes,
                    username=username,
                )

                # Reset db session_total_bytes
                sqlm.wipe_session_total_bytes(username=username)

                # Initialize ip timeouts
                now = time.monotonic()
                ip_timeout_updater(user_ip, user_mac, now, first_pass=True)

            except Exception as e:
                log.error(f"Error logging in user: {username}: {e}")

                log_out_user(username)

                # For flask_server
                raise RuntimeError(f"Error logging in user: {username}: {e}")

            return True
        else:
            raise sqlm.UserNameError(f"User {username} does not exist.")


def log_out_user(username):

    with USER_LOCKS[username]:

        try:
            remove_user_from_nftables(username)

            remove_user_from_ip_timeouts(username)

            sqlm.wipe_session_total_bytes(username=username)

            sqlm.logout_user_usage(username)

            log.info(f"Successfully logged out user {username}.")

        except Exception as e:
            log.error(f"Error logging out user {username}: {e}")
            return False

        return True


def log_out_all_users():
    usernames = sqlm.fetch_all_usernames_usage()

    if usernames:
        for username in usernames:
            log_out_user(username)
        log.info("All users logged out.")


def nftm_flush_set_ghosts():
    """Flush all IP addresses from sets that were never logged in."""
    nftm.flush_set(nftm.TABLE_FAMILY, nftm.TABLE_NAME, nftm.AUTH_SET_NAME)
    nftm.flush_set(nftm.TABLE_FAMILY, nftm.TABLE_NAME, nftm.HIGH_SPEED_SET_NAME)
    nftm.flush_set(nftm.TABLE_FAMILY, nftm.TABLE_NAME, nftm.THROTTLE_SET_NAME)


def delete_user_from_system(username):

    with QUOTA_LOCK, USER_LOCKS[username]:

        user_exists_usage = sqlm.check_if_user_exists(username)
        user_exists_radius = sqlm.check_if_user_exists(
            username, table_name="radcheck", db_path=sqlh.RADIUS_DB_PATH
        )

        if user_exists_usage:
            user_ip = sqlm.fetch_user_ip_address_usage(username)
            sqlm.delete_user_usage(username)

        if user_exists_radius:
            sqlm.delete_user_radius(username)

        remove_user_from_nftables(username, user_ip=user_ip)

        log.info(f"Successfully deleted user {username} from system.")


def delete_group_from_system(group_name):

    group_exists = sqlm.check_if_group_exists(group_name)

    if not group_exists:
        raise sqlm.GroupNameError(
            f"Failed to delete group {group_name}: Group does not exist."
        )

    sqlm.delete_group_usage(group_name)

    log.info(f"Successfully deleted group {group_name} from system.")


def delete_all_users_from_system():

    usernames = sqlm.fetch_all_usernames_usage()

    if usernames:
        for username in usernames:
            delete_user_from_system(username)


def system_hard_reset():
    log.info("System hard reset requested. System wipe in progress...")

    with RESET_LOCK:

        log_out_all_users()

        delete_all_users_from_system()

        # Delete all tables
        # Some problem with config initialization. So just updating, not wiping.
        all_tables = {
            sqlm.IP_TIMEOUT_TABLE_NAME: sqlh.USAGE_TRACKING_DB_PATH,
            sqlm.USAGE_TRACKING_TABLE_NAME: sqlh.USAGE_TRACKING_DB_PATH,
            sqlm.GROUP_TABLE_NAME: sqlh.USAGE_TRACKING_DB_PATH,
            sqlm.GROUP_USERS_TABLE_NAME: sqlh.USAGE_TRACKING_DB_PATH,
            sqlm.SYSTEM_STATE_TABLE_NAME: sqlh.USAGE_TRACKING_DB_PATH,
            sqlm.RADIUS_TABLE_NAME: sqlh.RADIUS_DB_PATH,
        }

        for table_name, db_path in all_tables.items():
            sqlh.wipe_table(table_name, db_path)
            log.debug(f"system_hard_reset: Wiped table {table_name}.")
            sqlh.log_all_table_information(table_name, db_path)

        # Delete all elements from nft sets
        nftm.flush_all_tracking_sets(nftm.TABLE_FAMILY, nftm.TABLE_NAME)

        # Default: Mon-Fri active (0-4), throttling off, mac limitation off
        sqlm.update_config_usage(
            name="default",
            system_name="dbtti",
            total_bytes=0,  # YOU should set this in admin page
            throttling_enabled=False,
            active_days=[0, 1, 2, 3, 4],
            mac_set_limitation=False,
            allowed_macs=None,
            active_config=1,
        )

        log.debug(f"system_hard_reset: Re-initialized config:")
        sqlh.log_all_table_information(sqlm.CONFIGS_TABLE_NAME)

        tz = dt.timezone(dt.timedelta(hours=sqlh.UTC_OFFSET))
        now = dt.datetime.now(tz)
        date_str = now.date().isoformat()

        try:
            config = sqlm.fetch_active_config()
        except sqlm.ConfigNameError as e:
            raise sqlm.DBInitializationError(f"Databases failed to iniitalize: {e}")

        system_name = config["system_name"]

        # Default: Mon-Fri active (0-4), throttling off, mac limitation off
        sqlm.initialize_system_state_usage(
            system_name=system_name,
            system_date=date_str,
            wiped_this_month=True,
            total_daily_bytes=0,
            total_monthly_bytes=0,
            all_time_bytes=0,
            num_users=0,
            num_groups=0,
            total_system_monthly_bytes=0,
            session_start_bytes=0,
            session_total_bytes=0,
            daily_budget_bytes=0,
            db_path=sqlh.USAGE_TRACKING_DB_PATH,
        )

        initialize_session_start_bytes_for_system(system_name)

        update_num_entities_system_state(num_users=0, num_groups=0)

        system_state = sqlm.fetch_system_state()
        log.debug(f"system_hard_reset: Re-initialized system state: {system_state}.")


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
    logged_out_users = []
    if usernames is not None:
        for username in usernames:
            logged_in = sqlm.check_if_user_logged_in(username)

            if logged_in:
                log.debug(
                    f"check_which_users_logged_in_for_ip_address: User {username} logged in at IP address {ip_addr}"
                )
                logged_in_users.append(username)
            else:
                logged_out_users.append(username)

    return logged_in_users, logged_out_users


def check_quota_ratio_legality(desired_quota_ratio, group_name=None, tol=1e-3):
    if desired_quota_ratio < 0 - tol or desired_quota_ratio > 1 + tol:
        raise ValueError("Desired quota ratio must be between 0 and 1.")

    quota_ratios = sqlm.fetch_desired_quota_ratios()  # [(group, ratio), ...]

    if quota_ratios is None:
        return True

    others_sum = fsum(r for g, r in quota_ratios if g != group_name)
    max_allowed = 1.0 - others_sum

    if desired_quota_ratio > max_allowed + tol:
        raise ValueError(
            f"Desired quota ratio too high; max allowed is {max_allowed:.6f} "
            f"(other groups sum to {others_sum:.6f})."
        )

    if group_name is not None:
        # pull min_quota_ratio from DB
        sql_group_info = sqlm.fetch_group_quota_info_usage()
        if sql_group_info is None:
            return True
        for g, n, desired, minr, maxb, minb, w in sql_group_info:
            if g == group_name and desired_quota_ratio < float(minr) - tol:
                raise ValueError(
                    f"Desired quota ratio for {group_name} must be ≥ {float(minr):.6f}."
                )

    return True


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

    users_logged_in_for_ip_addr, _ = check_which_users_logged_in_for_ip_address(ip_addr)

    if users_logged_in_for_ip_addr:

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
            remove_user_from_ip_timeouts(None, ip_addr)


def ip_timeout_enforcer():

    ip_and_mac_addrs = sqlm.fetch_all_ip_addr_ip_timeouts()

    if not ip_and_mac_addrs:
        return

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
                remove_user_from_ip_timeouts(None, ip_addr)
                log.debug(
                    f"ip_timeout_enforcer: Deleting user at {ip_addr} from ip_timeouts table"
                )
            else:
                log.debug(
                    f"ip_timeout_enforcer: ERROR: Failed to enforce timeout for user at {ip_addr}"
                )


def ip_enforce_timeout(ip_addr, mac_addr):

    usernames = sqlm.get_usernames_from_ip_and_mac_usage(ip_addr, mac_addr)

    # If somehow there are multiple users logged in with the same MAC / IP combo,
    # log them all out...
    if usernames:
        for username in usernames:
            success = log_out_user(username)

        # In future, maybe add to short DHCP lease pool.

        log.info(f"Timeout enforced for user at {ip_addr}")

        return success


def wipe_ip_neigh_db():
    sqlh.wipe_table(sqlm.IP_TIMEOUT_TABLE_NAME, sqlh.USAGE_TRACKING_DB_PATH)
    log.info("IP neigh db wiped.")


def system_daily_wipe_check(now):
    date_str = now.date().isoformat()

    system_state = sqlm.fetch_system_state()

    if system_state is None:
        sqlm.init_freeradius_db()
        sqlm.init_usage_db()
        return True

    system_date = system_state.get("system_date")

    if date_str != system_date:
        return False
    return True


def system_monthly_wipe_check():

    system_state = sqlm.fetch_system_state()

    if system_state is None:
        sqlm.init_freeradius_db()
        sqlm.init_usage_db()
        return True

    return system_state["wiped_this_month"]


def update_system_date(now):
    date_str = now.date().isoformat()
    sqlm.update_system_state_usage(system_date=date_str)


def update_monthly_wipe():
    sqlm.update_system_state_usage(wiped_this_month=True)


def update_daily_byte_budget(now=None):

    if now is None:
        tz = dt.timezone(dt.timedelta(hours=sqlh.UTC_OFFSET))
        now = dt.datetime.now(tz)

    total_monthly_bytes = (
        sqlm.fetch_config_total_bytes() - sqlm.fetch_total_system_monthly_usage_bytes()
    )

    weekdays_left = compute_remaining_weekdays(now, ACCOUNT_BILLING_DAY)

    sqlm.update_system_state_usage(
        daily_budget_bytes=total_monthly_bytes / weekdays_left
    )
