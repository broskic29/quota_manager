try:
    import nftables
except ImportError:  # dev/test environments
    nftables = None

import json
import logging
import subprocess

from quota_manager import sqlite_helper_functions as sqlh

# Need to figure out what default will be here. Use captive table, or modify fw4 table?
TABLE_FAMILY = "inet"
TABLE_NAME = "fw4"
AUTH_SET_NAME = "authorized_users"
THROTTLE_SET_NAME = "throttled_users"
HIGH_SPEED_SET_NAME = "high_speed_users"
DROP_SET_NAME = "dropped_users"

QUOTA_MANAGER_FORWARD_CHAIN_NAME = "quota_manager_forward"

WAN_IFACE_NAME = "eth0"

log = logging.getLogger(__name__)


class NFTSetMissingElementError(Exception):
    """Raised when an nftables set is missing an element it really should have."""

    pass


class NFTCommandError(RuntimeError):
    pass


def _nft_json(args: list[str], *, timeout_s: float = 2.0) -> dict[str, any]:
    """
    Run: nft -j <args...>
    Returns parsed JSON dict. Raises NFTCommandError on failure (including segfaults).
    """
    p = subprocess.run(
        ["nft", "-j", *args],
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    if p.returncode != 0:
        # If nft segfaults, you'll often see rc=139 and/or empty stderr.
        msg = (p.stderr or p.stdout or "").strip()
        raise NFTCommandError(f"nft failed rc={p.returncode}: {msg}")

    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError as e:
        raise NFTCommandError(
            f"nft returned invalid JSON: {e}. stdout={p.stdout!r}"
        ) from e


def operation_on_set_element(operation, table_family, table_name, set_name, element):
    if nftables is None:
        raise RuntimeError("nftables python bindings not installed")

    nft = nftables.Nftables()

    cmd_dict = {
        "nftables": [
            {
                operation: {
                    "element": {
                        "family": table_family,
                        "table": table_name,
                        "name": set_name,
                        "elem": element,
                    }
                }
            }
        ]
    }

    # in future, wrap in try block with error logging
    # nft.json_validate(cmd_dict)

    # Add error catching with these!
    rc, output, error = nft.json_cmd(cmd_dict)


def get_bytes_from_user(user_ip):
    if nftables is None:
        raise RuntimeError("nftables python bindings not installed")

    nft = nftables.Nftables()
    nft.set_json_output(True)
    rc, output, error = nft.cmd(
        f"list set {TABLE_FAMILY} {TABLE_NAME} {HIGH_SPEED_SET_NAME}"
    )
    sets = json.loads(output)["nftables"]

    elements = sets[1]["set"]

    if not "elem" in sets[1]["set"]:
        log.debug(f"Operation to fetch usage failed for user {user_ip}: set empty.")
        raise NFTSetMissingElementError(f"High speed users set empty.")

    elements = sets[1]["set"]["elem"]

    user_bytes = [
        elem["elem"]["counter"]["bytes"]
        for elem in elements
        if elem["elem"]["val"] == user_ip
    ]

    if len(user_bytes) < 1:
        log.debug(
            f"ERROR: Operation to fetch usage failed for user {user_ip}: IP address not in set."
        )
        raise sqlh.IPAddressError(f"Usage bytes undefined for user {user_ip}")

    return user_bytes[0]


def get_bytes_from_all_users():
    if nftables is None:
        raise RuntimeError("nftables python bindings not installed")

    nft = nftables.Nftables()
    nft.set_json_output(True)
    rc, output, error = nft.cmd(
        f"list set {TABLE_FAMILY} {TABLE_NAME} {HIGH_SPEED_SET_NAME}"
    )
    sets = json.loads(output)["nftables"]
    elements = sets[1]["set"]["elem"]
    counter_dict = {
        elem["elem"]["val"]: elem["elem"]["counter"]["bytes"] for elem in elements
    }
    return counter_dict


def get_system_bytes_subprocess(
    table_family: str,
    table_name: str,
    chain_name: str,
    wan_iface_name: str,
) -> int:
    """
    Sums rule counter bytes in a chain where the first expr is a match on iface == wan_iface_name,
    and the next expr contains a counter. Mirrors your prior logic but via subprocess.
    """
    data = _nft_json(["list", "chain", table_family, table_name, chain_name])
    items = data.get("nftables", [])
    rules = [it.get("rule") for it in items if "rule" in it]

    total = 0
    for rule in rules:
        expr = (rule or {}).get("expr", [])
        if len(expr) < 2:
            continue

        match = expr[0].get("match", {}) if isinstance(expr[0], dict) else {}
        right = match.get("right")
        maybe_counter = expr[1] if isinstance(expr[1], dict) else {}

        if right == wan_iface_name and "counter" in maybe_counter:
            total += int(maybe_counter["counter"].get("bytes", 0))

    return total


def get_system_bytes():
    if nftables is None:
        raise RuntimeError("nftables python bindings not installed")

    nft = nftables.Nftables()
    nft.set_json_output(True)
    rc, output, error = nft.cmd(
        f"list chain {TABLE_FAMILY} {TABLE_NAME} {QUOTA_MANAGER_FORWARD_CHAIN_NAME}"
    )

    try:
        chains = json.loads(output)["nftables"]
        rules = [item for item in chains if "rule" in item]
        counters = [
            (
                item.get("rule").get("expr")[1]
                if "counter" in item.get("rule").get("expr")[1]
                and item.get("rule").get("expr")[0].get("match").get("right")
                == WAN_IFACE_NAME
                else None
            )
            for item in rules
        ]
        counters = list(filter(lambda item: item is not None, counters))
        total_bytes = sum(map(lambda counter: counter["counter"]["bytes"], counters))

        return total_bytes
    except Exception as e:
        log.error(
            f"Failed to fetch system bytes: nftables rule configuration changed for chain {QUOTA_MANAGER_FORWARD_CHAIN_NAME}"
        )
        raise RuntimeError(
            f"Failed to fetch system bytes: nftables rule configuration changed for chain {QUOTA_MANAGER_FORWARD_CHAIN_NAME}"
        )


def flush_set(table_family, table_name, set_name):

    if nftables is None:
        raise RuntimeError("nftables python bindings not installed")

    nft = nftables.Nftables()
    nft.set_json_output(True)  # optional, for easier debugging

    # Build the JSON payload
    flush_payload = {
        "nftables": [
            {
                "flush": {
                    "set": {
                        "family": table_family,
                        "table": table_name,
                        "name": set_name,
                    }
                }
            }
        ]
    }

    # Send to nftables
    rc, out, err = nft.json_cmd(flush_payload)


def flush_all_tracking_sets(table_family, table_name):
    tracking_sets = [
        AUTH_SET_NAME,
        THROTTLE_SET_NAME,
        HIGH_SPEED_SET_NAME,
        DROP_SET_NAME,
    ]

    for set_name in tracking_sets:
        flush_set(table_family, table_name, set_name)


def check_if_elem_in_set(test_elem, table_family, table_name, set_name):
    if nftables is None:
        raise RuntimeError("nftables python bindings not installed")

    nft = nftables.Nftables()
    nft.set_json_output(True)

    # Build the JSON payload
    set_payload = {
        "nftables": [
            {
                "list": {
                    "set": {
                        "family": table_family,
                        "table": table_name,
                        "name": set_name,
                    }
                }
            }
        ]
    }

    rc, out, err = nft.json_cmd(set_payload)

    try:
        elements = out["nftables"][1]["set"]["elem"]

        res = [
            elem["elem"]["val"] for elem in elements if test_elem in elem["elem"]["val"]
        ]

        return bool(res)
    except (KeyError, TypeError):
        # log.debug(f"Element {test_elem} not in set {set_name}.")
        return False


def pull_elements_from_custom_sets(table_family, table_name):
    if nftables is None:
        raise RuntimeError("nftables python bindings not installed")

    nft = nftables.Nftables()
    nft.set_json_output(True)
    # Build the JSON payload
    table_payload = {
        "nftables": [
            {
                "list": {
                    "table": {
                        "family": table_family,
                        "name": table_name,
                    }
                }
            }
        ]
    }

    rc, out, err = nft.json_cmd(table_payload)

    nft_sets = [item for item in out["nftables"] if "set" in item]

    elem_dict = {
        nft_set["set"]["name"]: nft_set["set"]["elem"]
        for nft_set in nft_sets
        if "elem" in nft_set["set"]
    }

    return elem_dict


def check_if_user_authorized(user_ip):
    user_authed = check_if_elem_in_set(
        user_ip,
        TABLE_FAMILY,
        TABLE_NAME,
        AUTH_SET_NAME,
    )

    return user_authed


def check_if_user_throttled(user_ip):
    user_throttled = check_if_elem_in_set(
        user_ip,
        TABLE_FAMILY,
        TABLE_NAME,
        THROTTLE_SET_NAME,
    )

    return user_throttled


def check_if_user_dropped(user_ip):
    user_dropped = check_if_elem_in_set(
        user_ip,
        TABLE_FAMILY,
        TABLE_NAME,
        DROP_SET_NAME,
    )

    return user_dropped


def check_if_user_high_speed(user_ip):
    user_high_speed = check_if_elem_in_set(
        user_ip,
        TABLE_FAMILY,
        TABLE_NAME,
        HIGH_SPEED_SET_NAME,
    )

    return user_high_speed


def auth_ip(user_ip):

    # Add error checking
    if not check_if_user_authorized(user_ip):
        operation_on_set_element(
            "add",
            TABLE_FAMILY,
            TABLE_NAME,
            AUTH_SET_NAME,
            user_ip,
        )


def unauth_ip(user_ip):

    # Add error checking
    if check_if_user_authorized(user_ip):
        operation_on_set_element(
            "delete",
            TABLE_FAMILY,
            TABLE_NAME,
            AUTH_SET_NAME,
            user_ip,
        )


def throttle_ip(user_ip):

    # Add error checking
    if not check_if_user_throttled(user_ip):
        operation_on_set_element(
            "add",
            TABLE_FAMILY,
            TABLE_NAME,
            THROTTLE_SET_NAME,
            user_ip,
        )

    if check_if_user_high_speed(user_ip):
        operation_on_set_element(
            "delete",
            TABLE_FAMILY,
            TABLE_NAME,
            HIGH_SPEED_SET_NAME,
            user_ip,
        )

    if check_if_user_dropped(user_ip):
        operation_on_set_element(
            "delete",
            TABLE_FAMILY,
            TABLE_NAME,
            DROP_SET_NAME,
            user_ip,
        )


def drop_ip(user_ip):

    if check_if_user_throttled(user_ip):
        operation_on_set_element(
            "delete",
            TABLE_FAMILY,
            TABLE_NAME,
            THROTTLE_SET_NAME,
            user_ip,
        )

    if check_if_user_high_speed(user_ip):
        operation_on_set_element(
            "delete",
            TABLE_FAMILY,
            TABLE_NAME,
            HIGH_SPEED_SET_NAME,
            user_ip,
        )

    if not check_if_user_dropped(user_ip):
        operation_on_set_element(
            "add",
            TABLE_FAMILY,
            TABLE_NAME,
            DROP_SET_NAME,
            user_ip,
        )


def unthrottle_ip(user_ip):

    # Add error checking
    if check_if_user_throttled(user_ip):
        operation_on_set_element(
            "delete",
            TABLE_FAMILY,
            TABLE_NAME,
            THROTTLE_SET_NAME,
            user_ip,
        )

    if not check_if_user_high_speed(user_ip):
        operation_on_set_element(
            "add",
            TABLE_FAMILY,
            TABLE_NAME,
            HIGH_SPEED_SET_NAME,
            user_ip,
        )

    if check_if_user_dropped(user_ip):
        operation_on_set_element(
            "delete",
            TABLE_FAMILY,
            TABLE_NAME,
            DROP_SET_NAME,
            user_ip,
        )


def undrop_ip(user_ip):

    if check_if_user_throttled(user_ip):
        operation_on_set_element(
            "delete",
            TABLE_FAMILY,
            TABLE_NAME,
            THROTTLE_SET_NAME,
            user_ip,
        )

    if not check_if_user_high_speed(user_ip):
        operation_on_set_element(
            "add",
            TABLE_FAMILY,
            TABLE_NAME,
            HIGH_SPEED_SET_NAME,
            user_ip,
        )

    if check_if_user_dropped(user_ip):
        operation_on_set_element(
            "delete",
            TABLE_FAMILY,
            TABLE_NAME,
            DROP_SET_NAME,
            user_ip,
        )
