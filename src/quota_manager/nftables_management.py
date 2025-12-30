import nftables
import json

# Need to figure out what default will be here. Use captive table, or modify fw4 table?
TABLE_FAMILY = "inet"
CAPTIVE_TABLE_NAME = "captive"
THROTTLE_TABLE_NAME = "throttle"
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


def get_bytes_from_user(table_family, mac_address):
    nft = nftables.Nftables()
    nft.set_json_output(True)

    rc, output, error = nft.cmd(f"list counter {table_family} filter {mac_address}")

    counters = json.loads(output)["nftables"]

    return counters[1]["counter"]["bytes"]


def get_bytes_from_all_users(table_family):
    nft = nftables.Nftables()
    nft.set_json_output(True)

    rc, output, error = nft.cmd(f"list counter {table_family}")

    output_dict = json.loads(output)["nftables"]

    counters = [o["counter"] for o in output_dict if "counter" in o]

    counter_dict = {counter["name"]: counter["bytes"] for counter in counters}

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
