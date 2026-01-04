from flask import request, Response
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest, AccessAccept

from functools import wraps
from flask import Response
from werkzeug.security import check_password_hash, generate_password_hash
from socket import timeout

from quota_manager import sqlite_helper_functions as sqlh
from quota_manager import sql_management as sqlm

import logging
import re

log = logging.getLogger(__name__)


LOCALHOST = "127.0.0.1"

# FreeRADIUS configuration
RADIUS_SERVER = LOCALHOST
RADIUS_SECRET = b"BrFb+sewC8wGFb8+gD2UW3Fjf583PqoE"
RADIUS_PORT = 1812
RADIUS_DICTIONARY = "/etc/freeradius3/dictionary"

DEFAULT_SERVICE_TYPE = "Login-User"

UNEXPECTED_ERROR_MSG = "Unexpected error occurred."

ADMIN_PASSWORD_HASH = generate_password_hash("donbosco1815")

NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-@+]{3,32}$")


class UndefinedException(Exception):
    """Raised when behavior undefined for exception."""

    def __init__(self, original_exception):
        self.original_exception = original_exception
        super().__init__(f"Undefined exception occurred: {original_exception}")


def require_admin_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_password_hash(ADMIN_PASSWORD_HASH, auth.password):
            return Response(
                "Admin authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="Admin"'},
            )
        return f(*args, **kwargs)

    return decorated


def validate_name(name, label):
    if not name:
        return f"{label} is required."

    name = name.strip()

    if not NAME_RE.match(name):
        return f"Invalid {label}. " "Use 3–32 characters: letters, numbers, ., _"

    return None


def validate_positive_int(value, label, *, allow_zero=False, max_value=None):
    if value is None or value == "":
        return f"{label} is required."

    try:
        value = int(value)
    except (TypeError, ValueError):
        return f"{label} must be a numeric value."

    if value < 0 or (value == 0 and not allow_zero):
        return f"{label} must be greater than zero."

    if max_value is not None and value > max_value:
        return f"{label} must be ≤ {max_value}."

    return None


def error_appender(error, appendage):
    if error is None:
        error = appendage
    else:
        if appendage is not None:
            error += "\n" + appendage
    return error


# --- FreeRADIUS authentication ---
def authenticate_radius(username, password, ip_address, mac_address):
    srv = Client(
        server=RADIUS_SERVER,
        secret=RADIUS_SECRET,
        dict=Dictionary(RADIUS_DICTIONARY),
    )
    srv.AuthPort = RADIUS_PORT
    req = srv.CreateAuthPacket(
        code=AccessRequest,
        User_Name=username,
        User_Password=password,
        NAS_IP_Address=LOCALHOST,
        Framed_IP_Address=ip_address,
        Calling_Station_Id=mac_address,  # must be of format "00-04-5F-00-0F-D1"
        Service_Type=DEFAULT_SERVICE_TYPE,
    )
    req.add_message_authenticator()
    try:
        reply = srv.SendPacket(req)
        if reply.code == AccessAccept:
            log.info(f"RADIUS: User {username} successfully authenticated.")
            return True
        else:
            log.info(
                f"RADIUS: User {username} failed to authenticate. Reply code: {reply.code}"
            )

            table_exists = sqlh.check_if_table_exists("radcheck", sqlh.RADIUS_DB_PATH)

            if table_exists:
                table_empty = sqlh.check_if_table_empty("radcheck", sqlh.RADIUS_DB_PATH)
                if table_empty:
                    log.warning(f"RADIUS: Table is empty! Attempting to reinitialize.")
                    sqlm.init_freeradius_db()
                    log.info(f"RADIUS: Successfully reinitialized database.")
            else:
                log.warning(f"RADIUS: Table doesn't exist! Attempting to reinitialize.")
                sqlm.init_freeradius_db()
                log.info(f"RADIUS: Successfully reinitialized database.")

            return False
    except timeout:
        log.info(f"RADIUS: User {username} failed to authenticate.")
        return False


def safe_call(fn, error, msgs, *args, **kwargs):
    try:
        vals = fn(*args, **kwargs)
    except tuple(msgs) as e:
        log.exception(msgs[type(e)])
        return None, error_appender(error, msgs[type(e)])
    except Exception as e:
        log.exception(msgs["UndefinedException"])
        return None, error_appender(error, msgs["UndefinedException"])
    return vals, error
