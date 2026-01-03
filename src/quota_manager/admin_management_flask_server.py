from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import logging
import re

from functools import wraps
from flask import Response
from werkzeug.security import check_password_hash, generate_password_hash

import quota_manager.sql_management as sqlm
import quota_manager.sqlite_helper_functions as sqlh

admin_management_app = Flask(__name__)

log = logging.getLogger(__name__)

DEFAULT_PASSWORD = "password"

ADMIN_PASSWORD_HASH = generate_password_hash("donbosco1815")

NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-@+]{3,32}$")

new_user_form = """
<h2>Enter new user information:</h2>
<form method="post">
    Username: <input type="text" name="username" required><br><br>
    Group: <input type="text" name="group_name" required><br><br>
    <input type="submit" value="Create">
</form>
{% if error %}
<p style="color:red;">{{ error }}</p>
{% endif %}
"""

new_group_form = """
<h2>Enter new user information:</h2>
<form method="post">
    Group Name: <input type="text" name="group_name" required><br><br>
    High Speed Quota: <input type="text" name="high_speed_quota" required><br><br>
    Throttled Quota: <input type="text" name="throttled_quota" required><br><br>
    <input type="submit" value="Login">
</form>
{% if error %}
<p style="color:red;">{{ error }}</p>
{% endif %}
"""

admin_landing_page = """
<h1>Admin Panel</h1>

<ul>
    <li>
        <a href="/admin/new_user">
            <button>Create User</button>
        </a>
    </li>
    <li>
        <a href="/admin/new_group">
            <button>Create Group</button>
        </a>
    </li>
    <li>
        <a href="/admin/usage">
            <button>Usage Overview</button>
        </a>
    </li>
</ul>
"""


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
        return f"Invalid {label}. " "Use 3–32 characters: letters, numbers, ., -, _"

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


@admin_management_app.route("/admin")
@require_admin_auth
def admin_home():
    return render_template_string(admin_landing_page)


@admin_management_app.route("/admin/new_user", methods=["GET", "POST"])
@require_admin_auth
def create_user():
    error = None
    if request.method == "POST":
        data = request.form
        username = data.get("username")
        group_name = data.get("group_name")

        error = validate_name(username, "Username")
        if error:
            return render_template_string(new_user_form, error=error)

        error = validate_name(group_name, "Group Name")
        if error:
            return render_template_string(new_user_form, error=error)

        password = DEFAULT_PASSWORD

        sqlm.insert_user_radius(username, password, sqlh.RADIUS_DB_PATH)
        sqlm.insert_user_usage(
            username, mac_address="00:00:00:00:00", ip_address="0.0.0.0"
        )

        try:
            sqlm.insert_user_into_group_usage(group_name, username)
        except sqlm.UserNameError:
            log.error("User does not exist.")
            error = "User does not exist."
        except sqlm.GroupNameError:
            log.error("Group does not exist.")
            error = "Group does not exist."
        except Exception:
            log.exception("Unexpected error creating user")
            error = "Internal error while creating user."

        if error:
            return render_template_string(new_user_form, error=error)

        log.info(
            f"Succesfully created user {username} and assigned to group {group_name}."
        )
        return render_template_string("<h3>User creation succesful!</h3>")

    return render_template_string(new_user_form, error=error)


@admin_management_app.route("/admin/new_group", methods=["GET", "POST"])
@require_admin_auth
def create_group():
    error = None
    if request.method == "POST":
        data = request.form
        group_name = data.get("group_name")

        error = validate_name(group_name, "Group name")
        if error:
            return render_template_string(new_group_form, error=error)

        # Likely need to change this strucutre. Make an admin page where you can
        # dynamically determine quotas for all groups with a limit. If you input a value,
        # it will automatically change other values to make sure you are within the limit for high-speed-data.
        # Then just give a few (dynamically changing) options in a drop-down menu
        # for the admin to choose from when assigning a quota to a group.

        # Problems: assigning a new group will change the slice of the pie for each user.
        # Have to make quotas dynamically updating based on number of users on network.
        # Groups will simply have to be determined by proportionate slice of the pie.
        # Maybe just a few options like: high data quota, medium data quota, low data quota.
        # Groups should not be monkeyed with too much. Need to add another admin page that is
        # basically a tool to select quota values for high, medium, low.

        # There need to be default values selected that are simple. Then also give access to a design
        # tool to fine tune quotas.
        high_speed_quota = data.get("high_speed_quota")
        error = validate_positive_int(high_speed_quota, "High-speed Quota")
        if error:
            return render_template_string(new_group_form, error=error)

        throttled_quota = data.get("throttled_quota")
        error = validate_positive_int(throttled_quota, "Throttled Quota")
        if error:
            return render_template_string(new_group_form, error=error)

        high_speed_quota = int(high_speed_quota)
        throttled_quota = int(throttled_quota)

        sqlm.create_group_usage(
            group_name=group_name,
            high_speed_quota=high_speed_quota,
            throttled_quota=throttled_quota,
        )
        log.info(f"Succesfully created group {group_name}.")
        return render_template_string("<h3>Group creation successful!</h3>")

    return render_template_string(new_group_form)


@admin_management_app.route("/admin/usage")
@require_admin_auth
def usage_overview():
    return "<h2>Usage overview coming soon</h2>"


@admin_management_app.route("/")
def root():
    return redirect(url_for("admin_home"))
