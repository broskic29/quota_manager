from flask import Flask, request, render_template_string, redirect, Response

import logging

import quota_manager.sql_management as sqlm
import quota_manager.nftables_management as nftm
import quota_manager.quota_management as qm
import quota_manager.flask_utils as flu

user_login_app = Flask(__name__)
log = logging.getLogger(__name__)

login_form = """
<h2>Wi-Fi Login</h2>
<form method="post">
    Username: <input type="text" name="username" required><br><br>
    Password: <input type="password" name="password" required><br><br>
    <input type="submit" value="Login">
</form>
{% if error %}
<p style="color:red;">{{ error }}</p>
{% endif %}
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

        if flu.authenticate_radius(username, password, user_ip, user_mac):

            old_user_mac = None

            try:
                old_user_mac = sqlm.fetch_user_mac_address_usage(username)
            except nftm.MACAddressError:
                pass

            sqlm.login_user_usage(username, user_mac, user_ip)

            qm.mac_update(old_user_mac, user_mac, username)

            log.info(
                f"Login successful for {username}! User device {user_mac} at {user_ip} now has Internet access."
            )

            ua = request.headers.get("User-Agent", "")
            log.debug(ua)
            if "Apple" in ua or "Mac" in ua or "iPhone" in ua:
                # Apple CNA: return 200 Success to close portal
                return Response("Success", status=200, mimetype="text/html")
            elif "Android" in ua:
                # Android CNA: redirect 204
                return redirect("/generate_204")
            else:
                # Need to change to redirect to protected route user page at /login/username
                return render_template_string(
                    "<h3>Login successful!</h3><p>Device {{ mac }} now has Internet access.</p>",
                    mac=user_mac,
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

    username = sqlm.get_username_from_mac_address_usage(user_mac)

    if qm.is_user_authenticated(username, user_mac):
        log.info(
            f"User {username} authenticated. Logging in device at {user_mac}/{user_ip}..."
        )
        # Need to change to redirect to user page at /username
        return Response(status=204)
    else:
        return redirect("/login", 302)


@user_login_app.route("/hotspot-detect.html")
def apple_hotspot_detect():
    user_ip = request.remote_addr

    try:
        user_mac = qm.mac_from_ip(user_ip)
    except KeyError:
        return redirect("/login", 302)

    log.info(f"Login attempt from user at {user_mac}/{user_ip}.")

    username = sqlm.get_username_from_mac_address_usage(user_mac)

    if qm.is_user_authenticated(username, user_mac):
        log.info(
            f"User {username} authenticated. Loggin in device at {user_mac}/{user_ip}..."
        )
        # Need to change to redirect to user page at /username
        return Response("", status=200, mimetype="text/plain")
    else:
        return redirect("/login", 302)


@user_login_app.route("/connecttest.txt")
@user_login_app.route("/ncsi.txt")
def windows_ncsi():
    return redirect("/login", 302)


@user_login_app.route("/check_network_status.txt")
@user_login_app.route("/")
def linux_nm():
    return redirect("/login", 302)


@user_login_app.errorhandler(404)
def fallback(_):
    return redirect("/login", 302)
