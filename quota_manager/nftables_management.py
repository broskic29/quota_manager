import subprocess

TABLE_FAMILY = "inet"
CAPTIVE_TABLE_NAME = "captive"
THROTTLE_TABLE_NAME = "throttle"
AUTH_SET_NAME = "authorized_users"
THROTTLE_SET_NAME = "throttled_users"


def add_user_from_set(table_family, table_name, set_name, mac_address):
    subprocess.run(
        [
            "nft",
            "add",
            "element",
            f"{table_family}",
            f"{table_name}",
            f"{set_name}",
            "{",
            f"{mac_address}",
            "}",
        ],
        check=True,
    )


def delete_user_from_set(table_family, table_name, set_name, mac_address):
    subprocess.run(
        [
            "nft",
            "delete",
            "element",
            f"{table_family}",
            f"{table_name}",
            f"{set_name}",
            "{",
            f"{mac_address}",
            "}",
        ],
        check=True,
    )
