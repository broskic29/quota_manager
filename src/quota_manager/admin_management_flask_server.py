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
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Create New User</title>

<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        margin: 0;
        padding: 0;
        background: #f4f6f8;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
    }

    .container {
        background: white;
        padding: 2rem;
        border-radius: 12px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        width: 90%;
        max-width: 400px;
    }

    h2 {
        margin-bottom: 1.5rem;
        text-align: center;
        color: #333;
        font-size: 1.8rem;
    }

    form {
        display: flex;
        flex-direction: column;
        gap: 1rem;
    }

    label {
        display: flex;
        flex-direction: column;
        font-weight: bold;
        color: #555;
    }

    input[type="text"],
    select {
        padding: 0.6rem;
        font-size: 1rem;
        border: 1px solid #ccc;
        border-radius: 8px;
        margin-top: 0.3rem;
    }

    input[type="submit"] {
        padding: 0.9rem;
        font-size: 1.1rem;
        font-weight: bold;
        color: white;
        background-color: #007bff;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        transition: background-color 0.2s ease;
    }

    input[type="submit"]:hover {
        background-color: #0056b3;
    }

    .error-message {
        color: red;
        text-align: center;
        font-weight: bold;
    }
</style>
</head>
<body>
    <div class="container">
        <h2>Create New User</h2>
        <form method="post">
            <label>
                Username:
                <input type="text" name="username" placeholder="Enter username" required>
            </label>

            <label>
                Group:
                {% if groups %}
                    <select name="group_name" required>
                        {% for group in groups %}
                            <option value="{{ group }}">{{ group }}</option>
                        {% endfor %}
                    </select>
                {% else %}
                    <div style="margin-top: 0.5rem; color: #a00; font-size: 0.9rem;">
                        No groups exist yet.
                        <a href="http://192.168.3.1:5001/admin/new_group" style="color: #007bff; text-decoration: none;">
                            Create a group first.
                        </a>
                    </div>
                {% endif %}
            </label>

            <input
                type="submit"
                value="Create User"
                {% if not groups %}disabled style="opacity:0.6; cursor:not-allowed;"{% endif %}>

            <!-- Back link -->
            <div style="margin-top: 1.2rem; text-align: center;">
                <a href="http://192.168.3.1:5001/admin" style="color: #555; text-decoration: none; font-size: 0.9rem;">
                    ← Back to Admin Panel
                </a>
            </div>
        </form>


        {% if error %}
        <p class="error-message">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

new_group_form = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Create New Group</title>

<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        margin: 0;
        padding: 0;
        background: #f4f6f8;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
    }

    .container {
        background: white;
        padding: 2rem;
        border-radius: 12px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        width: 90%;
        max-width: 400px;
    }

    h2 {
        margin-bottom: 1.5rem;
        text-align: center;
        color: #333;
        font-size: 1.8rem;
    }

    form {
        display: flex;
        flex-direction: column;
        gap: 1rem;
    }

    label {
        display: flex;
        flex-direction: column;
        font-weight: bold;
        color: #555;
    }

    input[type="text"],
    input[type="number"],
    select {
        padding: 0.6rem;
        font-size: 1rem;
        border: 1px solid #ccc;
        border-radius: 8px;
        margin-top: 0.3rem;
    }

    select {
        width: 40%;
        margin-top: 0.3rem;
    }

    .quota-field {
        display: flex;
        gap: 0.5rem;
        align-items: center;
    }

    input[type="submit"] {
        padding: 0.9rem;
        font-size: 1.1rem;
        font-weight: bold;
        color: white;
        background-color: #007bff;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        transition: background-color 0.2s ease;
    }

    input[type="submit"]:hover {
        background-color: #0056b3;
    }

    .error-message {
        color: red;
        text-align: center;
        font-weight: bold;
    }
</style>
</head>
<body>
    <div class="container">
        <h2>Create New Group</h2>
        <form method="post">
            <label>
                Group Name:
                <input type="text" name="group_name" placeholder="Enter group name" required>
            </label>

            <label>
                High-Speed Quota:
                <div class="quota-field">
                    <input
                        type="number"
                        name="high_speed_quota"
                        min="0"
                        {% if high_speed_unit == "GB" %}
                            step="0.001"
                            placeholder="e.g. 1.250"
                        {% else %}
                            step="1"
                            placeholder="e.g. 1024"
                        {% endif %}
                        required
                    >
                    <select name="high_speed_unit">
                        <option value="MB" {% if high_speed_unit != "GB" %}selected{% endif %}>MB</option>
                        <option value="GB" {% if high_speed_unit == "GB" %}selected{% endif %}>GB</option>
                    </select>
                </div>
                <small style="display:block; color:#555; font-size:0.9em;">
                    1024 MB = 1 GB
                </small>
            </label>

            <label>
                Throttled Quota:
                <div class="quota-field">
                    <input
                        type="number"
                        name="throttled_quota"
                        min="0"
                        {% if throttled_unit == "GB" %}
                            step="0.001"
                            placeholder="e.g. 0.500"
                        {% else %}
                            step="1"
                            placeholder="e.g. 500"
                        {% endif %}
                        required
                    >
                    <select name="throttled_unit">
                        <option value="MB" {% if throttled_unit != "GB" %}selected{% endif %}>MB</option>
                        <option value="GB" {% if throttled_unit == "GB" %}selected{% endif %}>GB</option>
                    </select>
                </div>
                <small style="display:block; color:#555; font-size:0.9em;">
                    1024 MB = 1 GB
                </small>
            </label>


            <input type="submit" value="Create Group">

            <div style="margin-top: 1.5rem; text-align: center;">
                <a href="http://192.168.3.1:5001/admin" style="color: #007bff; text-decoration: none; font-size: 0.95rem;">
                    ← Back to Admin Panel
                </a>
            </div>
        </form>

        {% if error %}
        <p class="error-message">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

success_page = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Success</title>

<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: #f4f6f8;
        margin: 0;
        min-height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
    }

    .container {
        background: white;
        padding: 2rem;
        border-radius: 12px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        text-align: center;
        width: 90%;
        max-width: 400px;
    }

    h2 {
        color: #2d7a2d;
        margin-bottom: 1rem;
    }

    p {
        color: #444;
        margin-bottom: 2rem;
        font-size: 1rem;
    }

    a.button {
        display: inline-block;
        padding: 0.75rem 1.25rem;
        background-color: #007bff;
        color: white;
        text-decoration: none;
        font-weight: bold;
        border-radius: 8px;
        transition: background-color 0.2s ease;
    }

    a.button:hover {
        background-color: #0056b3;
    }
</style>
</head>
<body>
    <div style="margin-top: 1.5rem; text-align: center;">
        <p>{{ message }}</p>
        <a href="http://192.168.3.1:5001/admin" style="color: #007bff; text-decoration: none; font-size: 0.95rem;">
            ← Back to Admin Panel
        </a>
    </div>
</body>
</html>
"""


admin_landing_page = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Panel</title>

<!-- Font Awesome for icons -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" integrity="sha512-..." crossorigin="anonymous" referrerpolicy="no-referrer" />

<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        margin: 0;
        padding: 0;
        background: #f4f6f8;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
    }

    .container {
        text-align: center;
        background: white;
        padding: 2rem;
        border-radius: 12px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        width: 90%;
        max-width: 400px;
    }

    h1 {
        margin-bottom: 2rem;
        color: #333;
        font-size: 2rem;
    }

    .button-grid {
        display: flex;
        flex-direction: column;
        gap: 1rem;
    }

    .button-grid a {
        text-decoration: none;
    }

    .button-grid button {
        width: 100%;
        padding: 1rem;
        font-size: 1rem;
        font-weight: bold;
        color: white;
        background-color: #007bff;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
        transition: background-color 0.2s ease;
    }

    .button-grid button:hover {
        background-color: #0056b3;
    }

    .button-grid button {
        flex-direction: column;
    }

    @media (min-width: 500px) {
        .button-grid button {
            flex-direction: row;
        }
    }

</style>
</head>
<body>
    <div class="container">
        <h1>Admin Panel</h1>
        <div class="button-grid">
            <a href="/admin/new_user">
                <button><i class="fa-solid fa-user-plus"></i> Create User</button>
            </a>
            <a href="/admin/new_group">
                <button><i class="fa-solid fa-users"></i> Create Group</button>
            </a>
            <a href="/admin/usage">
                <button><i class="fa-solid fa-chart-pie"></i> Usage Overview</button>
            </a>
        </div>
    </div>
</body>
</html>
"""


@admin_management_app.route("/admin")
@flu.require_admin_auth
def admin_home():
    return render_template_string(admin_landing_page)


@admin_management_app.route("/admin/new_user", methods=["GET", "POST"])
@flu.require_admin_auth
def create_user():
    error = None
    existing_groups = []

    existing_groups, error = flu.safe_call(
        sqlm.get_groups_usage,
        error,
        None,
    )

    if error:
        return render_template_string(
            new_user_form, groups=existing_groups, error=error
        )

    if request.method == "POST":
        data = request.form
        username = data.get("username")
        group_name = data.get("group_name")

        error = flu.error_appender(error, flu.validate_name(username, "Username"))

        error = flu.error_appender(error, flu.validate_name(group_name, "Group Name"))
        if error:
            return render_template_string(
                new_user_form, groups=existing_groups, error=error
            )

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
            return render_template_string(
                new_user_form, groups=existing_groups, error=error
            )

        log.info(
            f"Succesfully created user {username} and assigned to group {group_name}."
        )
        return render_template_string(success_page, message="User creation successul!")

    return render_template_string(new_user_form, groups=existing_groups, error=error)


@admin_management_app.route("/admin/new_group", methods=["GET", "POST"])
@flu.require_admin_auth
def create_group():
    high_speed_unit = "MB"
    throttled_unit = "MB"
    error = None
    if request.method == "POST":
        data = request.form
        group_name = data.get("group_name")

        high_speed_unit = request.form.get("high_speed_unit", "MB")
        throttled_unit = request.form.get("throttled_unit", "MB")

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

        unit_multipliers = {"MB": 1024**2, "GB": 1024**3}

        high_speed_quota = float(data.get("high_speed_quota"))
        throttled_quota = float(data.get("throttled_quota"))

        high_speed_quota_bytes = int(
            high_speed_quota * unit_multipliers[data.get("high_speed_unit")]
        )
        throttled_quota_bytes = int(
            throttled_quota * unit_multipliers[data.get("throttled_unit")]
        )

        error = flu.error_appender(
            error, flu.validate_positive_int(high_speed_quota_bytes, "High-speed Quota")
        )
        error = flu.error_appender(
            error, flu.validate_positive_int(throttled_quota_bytes, "Throttled Quota")
        )
        if error:
            return render_template_string(
                new_group_form,
                high_speed_unit=high_speed_unit,
                throttled_unit=throttled_unit,
                error=error,
            )

        GROUP_CREATION_ERROR_MESSAGES = {
            IntegrityError: f"Failed to create group {group_name}: Group already exists.\n",
            flu.UndefinedException: f"Internal error creating user {group_name}. Please reload page.\n",
        }

        _, error = flu.safe_call(
            sqlm.create_group_usage,
            error,
            GROUP_CREATION_ERROR_MESSAGES,
            group_name,
            high_speed_quota_bytes,
            throttled_quota_bytes,
        )

        if error:
            return render_template_string(
                new_group_form,
                high_speed_unit=high_speed_unit,
                throttled_unit=throttled_unit,
                error=error,
            )

        log.info(f"Succesfully created group {group_name}.")
        return render_template_string(success_page, message="Group creation successul!")

    return render_template_string(
        new_group_form,
        high_speed_unit=high_speed_unit,
        throttled_unit=throttled_unit,
        error=error,
    )


@admin_management_app.route("/admin/usage")
@flu.require_admin_auth
def usage_overview():
    return "<h2>Usage overview coming soon</h2>"


@admin_management_app.route("/")
def root():
    return redirect(url_for("admin_home"))
