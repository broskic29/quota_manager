import nftables
import json
import logging

from quota_manager import sqlite_helper_functions as sqlh

# Need to figure out what default will be here. Use captive table, or modify fw4 table?
TABLE_FAMILY = "inet"
CAPTIVE_TABLE_NAME = "fw4"
THROTTLE_TABLE_NAME = "fw4"
AUTH_SET_NAME = "authorized_users"
THROTTLE_SET_NAME = "throttled_users"
HIGH_SPEED_SET_NAME = "high_speed_users"

log = logging.getLogger(__name__)


class NFTSetMissingElementError(Exception):
    """Raised when an nftables set is missing an element it really should have."""

    pass


def operation_on_set_element(operation, table_family, table_name, set_name, element):
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


def get_bytes_from_user(user_mac):
    nft = nftables.Nftables()
    nft.set_json_output(True)
    rc, output, error = nft.cmd(
        f"list set {TABLE_FAMILY} {CAPTIVE_TABLE_NAME} {AUTH_SET_NAME}"
    )
    sets = json.loads(output)["nftables"]

    elements = sets[1]["set"]

    if not "elem" in sets[1]["set"]:
        log.error(
            f"ERROR: Operation to fetch usage failed for user {user_mac}: set empty."
        )
        raise NFTSetMissingElementError(f"Authorized users set empty.")

    elements = sets[1]["set"]["elem"]

    user_bytes = [
        elem["elem"]["counter"]["bytes"]
        for elem in elements
        if elem["elem"]["val"] == user_mac
    ]

    if len(user_bytes) < 1:
        log.error(
            f"ERROR: Operation to fetch usage failed for user {user_mac}: MAC address not in set."
        )
        raise sqlh.MACAddressError(f"Usage bytes undefined for user {user_mac}")

    return user_bytes[0]


def get_bytes_from_all_users():
    nft = nftables.Nftables()
    nft.set_json_output(True)
    rc, output, error = nft.cmd(
        f"list set {TABLE_FAMILY} {CAPTIVE_TABLE_NAME} {AUTH_SET_NAME}"
    )
    sets = json.loads(output)["nftables"]
    elements = sets[1]["set"]["elem"]
    counter_dict = {
        elem["elem"]["val"]: elem["elem"]["counter"]["bytes"] for elem in elements
    }
    return counter_dict


def flush_set(table_family, table_name, set_name):

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


def check_if_elem_in_set(test_elem, table_family, table_name, set_name):
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

    elements = out["nftables"][1]["set"]["elem"]

    res = [elem["elem"]["val"] for elem in elements if test_elem in elem["elem"]["val"]]

    return bool(res)


def pull_elements_from_custom_sets(table_family, table_name):
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
