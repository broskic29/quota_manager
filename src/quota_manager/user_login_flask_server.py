from flask import Flask, request, render_template_string, redirect, Response

import logging

import quota_manager.sql_management as sqlm
import quota_manager.nftables_management as nftm
import quota_manager.quota_management as qm
import quota_manager.flask_utils as flu

user_login_app = Flask(__name__)
log = logging.getLogger(__name__)

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

.error-message {
    color: red;
    margin-top: 15px;
    text-align: center;
    font-size: 0.9rem;
}
</style>

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
    <div class="container">
        <p>{{ message }}</p>
        <a href="http://192.168.3.1:5000/login" style="color: #007bff; text-decoration: none; font-size: 0.95rem;">
            ← Back to Login Page
        </a>
    </div>
</body>
</html>
"""

iphone_success_page = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Success</title>
    <style>
        body {{
            font-family: system-ui, sans-serif;
            background-color: #f7f7f7;
            color: #222;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 1rem;
        }}
        .message-box {{
            background: #fff;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
        }}
        h2 {{ margin-top: 0; font-size: 1.5rem; color: #333; }}
        p {{ font-size: 1rem; margin: 1rem 0 0 0; }}
        small {{ display: block; font-size: 0.85rem; color: #666; margin-top: 0.5rem; }}
    </style>
</head>
<body>
    <div class="message-box">
        <h2>Success!</h2>
        <p>Login successful! Device now has Internet access.</p>
        <small>Please press 'Cancel' or 'Done' in the top right corner, then select the 'Use without internet' option.</small>
    </div>
</body>
</html>
"""


# --- Routes ---
@user_login_app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user_ip = request.remote_addr

        USER_LOGIN_ERROR_MESSAGES = {
            nftm.MACAddressError: f"Login failed. MAC address for user {username} could not be determined. Please disconnect from network and try again.",
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

            old_user_mac = None

            try:
                old_user_mac = sqlm.fetch_user_mac_address_usage(username)
            except nftm.MACAddressError:
                pass

            if error:
                return render_template_string(login_form, error=error)

            old_username_for_mac_address, _ = flu.safe_call(
                qm.check_which_user_logged_in_for_mac_address,
                error,
                USER_LOGIN_ERROR_MESSAGES,
                user_mac,
            )

            session_start_bytes = 0

            if old_username_for_mac_address:

                session_start_bytes, error = flu.safe_call(
                    qm.initialize_session_start_bytes,
                    error,
                    USER_LOGIN_ERROR_MESSAGES,
                    user_mac,
                )

                if error:
                    return render_template_string(login_form, error=error)

                _, error = flu.safe_call(
                    qm.log_out_user,
                    error,
                    USER_LOGIN_ERROR_MESSAGES,
                    old_username_for_mac_address,
                )

                if error:
                    return render_template_string(login_form, error=error)

            _, error = flu.safe_call(
                sqlm.wipe_session_total_bytes,
                error,
                USER_LOGIN_ERROR_MESSAGES,
                username,
            )

            if error:
                return render_template_string(login_form, error=error)

            _, error = flu.safe_call(
                sqlm.login_user_usage,
                error,
                USER_LOGIN_ERROR_MESSAGES,
                username,
                user_mac,
                user_ip,
                session_start_bytes,
            )

            if error:
                return render_template_string(login_form, error=error)

            _, error = flu.safe_call(
                qm.mac_update,
                error,
                USER_LOGIN_ERROR_MESSAGES,
                old_user_mac,
                user_mac,
            )

            if error:
                return render_template_string(login_form, error=error)

            log.info(
                f"Login successful for {username}! User device {user_mac} at {user_ip} now has Internet access."
            )

            ua = request.headers.get("User-Agent", "")
            log.debug(ua)
            if ("Apple" in ua or "Mac" in ua) and "iPhone" not in ua:
                log.info(
                    f"Apple device detected for {user_mac}, returning regular page"
                )
                return render_template_string(
                    success_page,
                    message=f"Login successful! Device {user_mac} now has Internet access.",
                )
            elif "iPhone" in ua:
                # Apple CNA: return 200 Success to close portal
                log.info(f"iPhone CNA detected for {user_mac}, returning 200")
                return Response(
                    iphone_success_page,
                    status=200,
                    mimetype="text/html",
                )
            elif "Android" in ua:
                # Android CNA: redirect 204
                log.info(f"Android CNA detected for {user_mac}, returning 204")
                return Response(
                    iphone_success_page,
                    status=204,
                    mimetype="text/html",
                )
            else:
                log.info(
                    f"Other device detected for {user_mac}, returning regular page"
                )
                return render_template_string(
                    success_page,
                    message=f"Login successful! Device {user_mac} now has Internet access.",
                )
        else:
            log.info(f"Login unsuccessful. Invalid username or password")
            error = flu.error_appender(error, "Invalid username or password")
    return render_template_string(login_form, error=error)


# Add redirect for captive detection for different devices
@user_login_app.route("/generate_204")
def android_generate_204():
    user_ip = request.remote_addr

    try:
        user_mac = qm.mac_from_ip(user_ip)
    except KeyError:
        return redirect("/login", 302)

    log.info(f"Login attempt from user at {user_mac}/{user_ip}.")

    return redirect("/login", 302)


@user_login_app.route("/hotspot-detect.html")
def apple_hotspot_detect():
    user_ip = request.remote_addr

    try:
        user_mac = qm.mac_from_ip(user_ip)
    except KeyError:
        return redirect("/login", 302)

    log.info(f"Login attempt from user at {user_mac}/{user_ip}.")

    return redirect("/login", 302)


@user_login_app.route("/clients3.google.com")
@user_login_app.route("/connectivitycheck.gstatic.com")
@user_login_app.route("/connectivitycheck.android.com")
@user_login_app.route("/connecttest.txt")
@user_login_app.route("/ncsi.txt")
def windows_ncsi():
    return redirect("/login", 302)


@user_login_app.route("/ipv6.msftncsi.com")
@user_login_app.route("/ipv4.msftncsi.com")
@user_login_app.route("/www.msftncsi.com")
@user_login_app.route("/check_network_status.txt")
@user_login_app.route("/")
def linux_nm():
    return redirect("/login", 302)


@user_login_app.errorhandler(404)
def fallback(_):
    return redirect("/login", 302)
