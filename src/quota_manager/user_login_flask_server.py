from flask import (
    Flask,
    request,
    render_template_string,
    redirect,
    Response,
    url_for,
    session,
)
from urllib.parse import quote

import logging

import quota_manager.sql_management as sqlm
import quota_manager.sqlite_helper_functions as sqlh
import quota_manager.nftables_management as nftm
import quota_manager.quota_management as qm
import quota_manager.flask_utils as flu

user_app = Flask(__name__)
user_app.secret_key = "donbosco1815"

log = logging.getLogger(__name__)

GENERAL_ERROR_MESSAGE = {
    flu.UndefinedException: "Internal error creating user. Please reload page.",
}

login_form = """
<div class="form-container">
    <h2>Wi-Fi Login</h2>

    <form method="post">
        <label>
            Username:
            <input type="text" name="username" required placeholder="Enter your username">
        </label>

        <label>
            Password:
            <input type="password" name="password" required placeholder="Enter your password">
        </label>

        <input type="submit" value="Login">
    </form>

    {% if message %}
    <p class="message">{{ message }}</p>
    {% endif %}

    {% if error %}
    <p class="error-message">{{ error }}</p>
    {% endif %}
</div>

<style>
.form-container {
    max-width: 400px;
    margin: 40px auto;
    padding: 20px 25px;
    border-radius: 10px;
    background-color: #f8f9fa;
    box-shadow: 0 6px 12px rgba(0,0,0,0.1);
    font-family: Arial, sans-serif;
}

h2 {
    text-align: center;
    color: #333;
    margin-bottom: 20px;
}

form label {
    display: block;
    margin-bottom: 15px;
    font-weight: 500;
    color: #444;
}

form input[type="text"],
form input[type="password"] {
    width: 100%;
    padding: 10px 12px;
    font-size: 1rem;
    margin-top: 5px;
    border: 1px solid #ccc;
    border-radius: 6px;
    box-sizing: border-box;
}

form input[type="submit"] {
    width: 100%;
    padding: 10px 12px;
    font-size: 1rem;
    background-color: #007bff;
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    transition: background-color 0.2s ease;
}

form input[type="submit"]:hover {
    background-color: #0056b3;
}

.message {
    color: black;
    margin-top: 15px;
    text-align: center;
    font-size: 0.9rem;
}

.error-message {
    color: red;
    margin-top: 15px;
    text-align: center;
    font-size: 0.9rem;
}

</style>

"""

user_dashboard_template = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Welcome, {{ username }}.</title>

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
        margin-bottom: 1.5rem;
        color: #333;
        font-size: 2rem;
    }

    .usage {
        font-size: 2rem;
        margin: 2rem 0;
        font-weight: bold;
        color: #007bff;
    }

    .quota_message {
        font-size: 1rem;
        margin: 2rem 0;
        font-weight: bold;
        color: #007bff;
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

    .bottom-buttons {
        display: flex;
        gap: 1rem;
        margin-top: 2rem;
    }

    .bottom-buttons button {
        flex: 1;
    }

    @media (min-width: 500px) {
        .button-grid button {
            flex-direction: row;
        }
    }

    .message {
        color: black;
        margin-top: 1.5rem;
        text-align: center;
        font-size: 0.9rem;
    }

    .error-message {
        color: red;
        margin-top: 15px;
        text-align: center;
        font-size: 0.9rem;
    }

</style>
</head>
<body>
    <div class="container">
        <h1>User Dashboard</h1>

        <!-- Dynamic daily usage -->
        <div class="usage">
            {{ daily_usage | round(2) }} {{ usage_byte_unit }} / {{ quota | round(2) }} {{ quota_byte_unit }}
        </div>

        <!-- Quota message -->
        <div class="quota_message" style="color: {% if exceeds_quota %}red{% else %}black{% endif %}; font-size: {% if exceeds_quota %}1rem{% else %}0.5rem{% endif %};">
            {% if exceeds_quota %}
                You are over quota! Data will reset at 24:00.
            {% else %}
                You are under quota.
            {% endif %}
        </div>

        <div class="bottom-buttons">
            <a href="/user/{{ username }}/logout"><button><i class="fa-solid fa-sign-out-alt"></i> Log Out</button></a>
            <a href="/user/{{ username }}/change_password"><button><i class="fa-solid fa-key"></i> Change Password</button></a>
        </div>

        {% if message %}
        <p class="message">{{ message }}</p>
        {% endif %}

        {% if error %}
        <p class="error-message">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

password_change_form = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Change Password</title>
<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: #f4f6f8;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        margin: 0;
    }
    .container {
        background: white;
        padding: 2rem;
        border-radius: 12px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        width: 90%;
        max-width: 400px;
        text-align: center;
    }
    h1 {
        margin-bottom: 1.5rem;
        color: #333;
    }
    form {
        display: flex;
        flex-direction: column;
        gap: 1rem;
    }
    input {
        padding: 0.8rem;
        font-size: 1rem;
        border: 1px solid #ccc;
        border-radius: 8px;
    }
    button {
        padding: 1rem;
        font-size: 1rem;
        font-weight: bold;
        color: white;
        background-color: #007bff;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        transition: background-color 0.2s ease;
    }
    button:hover {
        background-color: #0056b3;
    }
    .error {
        color: red;
        font-weight: bold;
        margin-bottom: 1rem;
    }
</style>
</head>
<body>
    <div class="container">
        <h1>Change Password</h1>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="post">
            <input type="password" name="current_password" placeholder="Current Password" required>
            <input type="password" name="new_password" placeholder="New Password" required>
            <input type="password" name="confirm_password" placeholder="Confirm New Password" required>
            <button type="submit">Change Password</button>
        </form>
    </div>
</body>
</html>
"""


# --- Routes ---
@user_app.route("/login", methods=["GET", "POST"])
def login():

    msg = session.pop("message", "")
    error = session.pop("error", "")
    captive = session.pop("captive", False)

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user_ip = request.remote_addr

        USER_LOGIN_ERROR_MESSAGES = {
            sqlh.IPAddressError: f"Login failed. IP address for user {username} could not be determined. Please disconnect from network and try again.",
            sqlm.UserNameError: f"Failed attempting to log in user {username}: User does not exist.",
            flu.UndefinedException: "Internal error creating user. Please reload page.",
        }

        user_mac, error = flu.safe_call(
            qm.mac_from_ip,
            error,
            USER_LOGIN_ERROR_MESSAGES,
            user_ip,
        )

        if error:
            return render_template_string(login_form, error=error)

        rad_auth, error = flu.safe_call(
            flu.authenticate_radius,
            error,
            USER_LOGIN_ERROR_MESSAGES,
            username,
            password,
            user_ip,
            user_mac,
        )

        if error:
            return render_template_string(login_form, error=error)

        if rad_auth:

            session["username"] = username

            _, error = flu.safe_call(
                qm.log_in_user,
                error,
                USER_LOGIN_ERROR_MESSAGES,
                username,
                user_ip,
                user_mac,
            )

            if error:
                return render_template_string(login_form, error=error)

            log.info(
                f"Login successful for {username}! User device {user_mac} at {user_ip} now has Internet access."
            )

            ua = request.headers.get("User-Agent", "")
            log.debug(ua)

            if captive:
                # Apple / Mac (non-iPhone)
                if ("Apple" in ua or "Mac" in ua) and "iPhone" not in ua:
                    log.info(
                        f"Apple device detected for {user_mac}, returning regular page"
                    )
                    msg = (
                        f"Login successful! Device {user_mac} now has Internet access."
                    )
                    session["message"] = msg
                    return redirect(url_for("user_dashboard", username=username))

                # iPhone CNA
                elif "iPhone" in ua:
                    log.info(f"iPhone CNA detected for {user_mac}, returning 200")
                    return Response(status=200)  # <-- returns blank 200 success

                # Android CNA
                elif "Android" in ua:
                    log.info(f"Android CNA detected for {user_mac}, returning 204")
                    return Response(status=204)  # <-- returns blank 204

                # Other devices
                else:
                    log.info(
                        f"Other device detected for {user_mac}, returning regular page"
                    )
                    msg = (
                        f"Login successful! Device {user_mac} now has Internet access."
                    )
                    session["message"] = msg
                    return redirect(url_for("user_dashboard", username=username))

            return redirect(url_for("user_dashboard", username=username))

        else:
            log.info(f"Login unsuccessful. Invalid username or password")
            error += flu.error_appender(error, "Invalid username or password")
            return render_template_string(login_form, error=error)

    return render_template_string(login_form, message=msg, error=error)


@user_app.route("/user/<username>/dashboard", methods=["GET", "POST"])
def user_dashboard(username):

    msg = session.pop("message", "")
    error = session.pop("error", "")

    # SESSION AUTHENTICATION CHECK (#6)
    if session.get("username") != username:
        return redirect(url_for("login"))

    USER_DASHBOARD_ERROR_MESSAGES = {
        flu.UndefinedException: f"Internal error attempting to display usage for user {username}. Please reload page.",
    }

    quota_vals, error = flu.safe_call(
        qm.evaluate_user_bytes_against_quota,
        error,
        USER_DASHBOARD_ERROR_MESSAGES,
        username,
    )

    if error:

        msg += f"Login successful! User {username} now has Internet access."
        session["message"] = msg
        session["error"] = error
        return redirect(url_for("login"))

    user_exceeds_quota, daily_usage_bytes, quota_bytes = quota_vals

    usage_byte_quantity, usage_byte_unit = flu.byte_conversion(daily_usage_bytes)
    quota_byte_quantity, quota_byte_unit = flu.byte_conversion(quota_bytes)

    return render_template_string(
        user_dashboard_template,
        error=error,
        message=msg,
        username=username,
        exceeds_quota=user_exceeds_quota,
        daily_usage=usage_byte_quantity,
        quota=quota_byte_quantity,
        usage_byte_unit=usage_byte_unit,
        quota_byte_unit=quota_byte_unit,
    )


@user_app.route("/user/<username>/change_password", methods=["GET", "POST"])
def change_password(username):

    msg = session.pop("message", "")
    error = session.pop("error", "")

    USER_PASSWORD_CHANGE_ERROR_MESSAGES = {
        flu.UndefinedException: f"Internal error attempting to display usage for user {username}. Please reload page.",
    }

    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Check current password
        user_password, error = flu.safe_call(
            sqlm.get_user_password_radius,
            error,
            USER_PASSWORD_CHANGE_ERROR_MESSAGES,
            username,
        )

        if error:
            session["error"] = error
            return redirect(url_for("change_password", username=username))

        if current_password != user_password:
            error = "Current password is incorrect."
            session["error"] = error
            return redirect(url_for("change_password", username=username))
        # Check new passwords match
        elif new_password != confirm_password:
            error = "New passwords do not match."
            session["error"] = error
            return redirect(url_for("change_password", username=username))
        else:
            # Update password

            # Check current password
            user_password, error = flu.safe_call(
                sqlm.modify_user_password_radius,
                error,
                USER_PASSWORD_CHANGE_ERROR_MESSAGES,
                username,
                new_password,
            )

            if error:
                session["error"] = error
                return redirect(url_for("login"))

            # Redirect to landing page after success
            msg += f"Successfully changed password for user {username}."
            session["message"] = msg
            return redirect(url_for("user_dashboard", username=username))

    return render_template_string(password_change_form, error=error)


@user_app.route("/user/<username>/logout")
def logout(username):

    if session.get("username") != username:
        return redirect(url_for("login"))

    session.pop("username", None)

    msg = session.pop("message", "")
    error = session.pop("error", "")

    USER_LOGOUT_ERROR_MESSAGES = {
        flu.UndefinedException: "Internal error logging out user. Please try again.",
    }

    _, error = flu.safe_call(
        qm.log_out_user,
        error,
        USER_LOGOUT_ERROR_MESSAGES,
        username,
    )

    if error:
        session["error"] = error
        return redirect(url_for("user_dashboard", username=username))

    if error:
        session["error"] = error
        return redirect(url_for("login"))

    msg += f"User {username} successfully logged out."
    return redirect(url_for("login"))


# Add redirect for captive detection for different devices
@user_app.route("/generate_204")
def android_generate_204():

    session["captive"] = True

    user_ip = request.remote_addr

    user_mac, error = flu.safe_call(
        qm.mac_from_ip,
        error,
        GENERAL_ERROR_MESSAGE,
        user_ip,
    )

    if error:
        session["error"] = error
        return redirect("/login", 302)

    log.info(f"Login attempt from user at {user_mac}/{user_ip}.")

    return redirect("/login", 302)


@user_app.route("/hotspot-detect.html")
def apple_hotspot_detect():
    session["captive"] = True
    user_ip = request.remote_addr

    user_mac, error = flu.safe_call(
        qm.mac_from_ip,
        error,
        GENERAL_ERROR_MESSAGE,
        user_ip,
    )

    if error:
        session["error"] = error
        return redirect("/login", 302)

    log.info(f"Login attempt from user at {user_mac}/{user_ip}.")

    msg = "\nIf you are on iPhone, please press the 'cancel' button in the top right, then select 'Use Without Internet'."
    session["message"] = msg
    return redirect(url_for("login"))


@user_app.route("/clients3.google.com")
@user_app.route("/connectivitycheck.gstatic.com")
@user_app.route("/connectivitycheck.android.com")
@user_app.route("/connecttest.txt")
@user_app.route("/ncsi.txt")
def windows_ncsi():
    session["captive"] = True
    return redirect("/login", 302)


@user_app.route("/ipv6.msftncsi.com")
@user_app.route("/ipv4.msftncsi.com")
@user_app.route("/www.msftncsi.com")
@user_app.route("/check_network_status.txt")
@user_app.route("/")
def linux_nm():
    session["captive"] = True
    return redirect("/login", 302)


@user_app.errorhandler(404)
def fallback(_):
    session["captive"] = True
    return redirect("/login", 302)
