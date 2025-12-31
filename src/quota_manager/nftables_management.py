import nftables
import json

# Need to figure out what default will be here. Use captive table, or modify fw4 table?
TABLE_FAMILY = "inet"
CAPTIVE_TABLE_NAME = "fw4"
THROTTLE_TABLE_NAME = "fw4"
AUTH_SET_NAME = "authorized_users"
THROTTLE_SET_NAME = "throttled_users"
HIGH_SPEED_SET_NAME = "high_speed_users"


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

    elements = sets[1]["set"]["elem"]
    user_bytes = [
        elem["elem"]["counter"]["bytes"]
        for elem in elements
        if elem["elem"]["val"] == user_mac
    ]

    if user_bytes is not None:
        user_bytes = user_bytes[0]
    else:
        print("User MAC address not in Authorized Users set")
        user_bytes = None

    return user_bytes


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
