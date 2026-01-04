from flask import Flask, request, render_template_string, redirect, url_for
from sqlite3 import IntegrityError
import logging

import quota_manager.sql_management as sqlm
import quota_manager.sqlite_helper_functions as sqlh
import quota_manager.flask_utils as flu

admin_management_app = Flask(__name__)

log = logging.getLogger(__name__)

DEFAULT_PASSWORD = "password"

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
    <input type="submit" value="Create">
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


@admin_management_app.route("/admin")
@flu.require_admin_auth
def admin_home():
    return render_template_string(admin_landing_page)


@admin_management_app.route("/admin/new_user", methods=["GET", "POST"])
@flu.require_admin_auth
def create_user():
    error = None
    if request.method == "POST":
        data = request.form
        username = data.get("username")
        group_name = data.get("group_name")

        error = flu.error_appender(error, flu.validate_name(username, "Username"))

        error = flu.error_appender(error, flu.validate_name(group_name, "Group Name"))
        if error:
            return render_template_string(new_user_form, error=error)

        USER_CREATION_ERROR_MESSAGES = {
            sqlm.UserNameError: f"Failed to create user {username}: User already exists.\n",
            sqlm.GroupNameError: f"Failed inserting user {username} into group {group_name}: No group by name {group_name} exists.\n",
            IntegrityError: f"Failed to create user {username}: User already exists.\n",
            flu.UndefinedException: f"Internal error creating user {username}. Please reload page.\n",
        }

        _, error = flu.safe_call(
            sqlm.insert_user_radius,
            error,
            USER_CREATION_ERROR_MESSAGES,
            username,
            DEFAULT_PASSWORD,
            sqlh.RADIUS_DB_PATH,
        )

        _, error = flu.safe_call(
            sqlm.create_user_usage,
            error,
            USER_CREATION_ERROR_MESSAGES,
            username,
            group_name,
        )

        if error:
            return render_template_string(new_user_form, error=error)

        log.info(
            f"Succesfully created user {username} and assigned to group {group_name}."
        )
        return render_template_string("<h3>User creation succesful!</h3>")

    return render_template_string(new_user_form, error=error)


@admin_management_app.route("/admin/new_group", methods=["GET", "POST"])
@flu.require_admin_auth
def create_group():
    error = None
    if request.method == "POST":
        data = request.form
        group_name = data.get("group_name")

        error = flu.error_appender(error, flu.validate_name(group_name, "Group name"))

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
        error = flu.error_appender(
            error, flu.validate_positive_int(high_speed_quota, "High-speed Quota")
        )

        throttled_quota = data.get("throttled_quota")
        error = flu.error_appender(
            error, flu.validate_positive_int(throttled_quota, "Throttled Quota")
        )
        if error:
            return render_template_string(new_group_form, error=error)

        GROUP_CREATION_ERROR_MESSAGES = {
            IntegrityError: f"Failed to create group {group_name}: Group already exists.\n",
            flu.UndefinedException: f"Internal error creating user {group_name}. Please reload page.\n",
        }

        high_speed_quota = int(high_speed_quota)
        throttled_quota = int(throttled_quota)

        _, error = flu.safe_call(
            sqlm.create_group_usage,
            error,
            GROUP_CREATION_ERROR_MESSAGES,
            group_name,
            high_speed_quota,
            throttled_quota,
        )

        if error:
            return render_template_string(new_group_form, error=error)

        log.info(f"Succesfully created group {group_name}.")
        return render_template_string("<h3>Group creation successful!</h3>")

    return render_template_string(new_group_form)


@admin_management_app.route("/admin/usage")
@flu.require_admin_auth
def usage_overview():
    return "<h2>Usage overview coming soon</h2>"


@admin_management_app.route("/")
def root():
    return redirect(url_for("admin_home"))
