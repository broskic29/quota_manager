from flask import Flask, request, render_template_string, redirect, Response

import logging

import quota_manager.sql_management as sqlm
import quota_manager.sqlite_helper_functions as sqlh
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
            sqlh.MACAddressError: f"Login failed. MAC address for user {username} could not be determined. Please disconnect from network and try again.",
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

        if flu.authenticate_radius(username, password, user_ip, user_mac):

            if error:
                return render_template_string(login_form, error=error)

            # Check if someone else was previously logged in with that mac address
            old_username_for_mac_address, _ = flu.safe_call(
                qm.check_which_user_logged_in_for_mac_address,
                error,
                USER_LOGIN_ERROR_MESSAGES,
                user_mac,
            )

            if error:
                return render_template_string(login_form, error=error)

            if old_username_for_mac_address is not username:

                _, error = flu.safe_call(
                    qm.log_out_user,
                    error,
                    USER_LOGIN_ERROR_MESSAGES,
                    old_username_for_mac_address,
                )

                if error:
                    return render_template_string(login_form, error=error)

            # Should be wiped on logout, but wiping again just in case
            _, error = flu.safe_call(
                sqlm.wipe_session_total_bytes,
                error,
                USER_LOGIN_ERROR_MESSAGES,
                username,
            )

            if error:
                return render_template_string(login_form, error=error)

            session_start_bytes = 0

            session_start_bytes, error = flu.safe_call(
                qm.initialize_session_start_bytes,
                error,
                USER_LOGIN_ERROR_MESSAGES,
                user_mac,
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

            log.info(
                f"Login successful for {username}! User device {user_mac} at {user_ip} now has Internet access."
            )

            ua = request.headers.get("User-Agent", "")
            log.debug(ua)
            if "Apple" in ua or "Mac" in ua:
                return render_template_string(
                    "<h3>Login successful!</h3><p>Device {{ mac }} now has Internet access.</p>",
                    mac=user_mac,
                )
            elif "iPhone" in ua:
                # Apple CNA: return 200 Success to close portal
                return Response(
                    "Success! Please press 'Cancel' and then select the 'Use without internet' option.",
                    status=200,
                    mimetype="text/html",
                )
            elif "Android" in ua:
                # Android CNA: redirect 204
                return redirect("/generate_204")
            else:
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
