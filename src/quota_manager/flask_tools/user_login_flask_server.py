from flask import (
    Flask,
    request,
    render_template_string,
    redirect,
    Response,
    url_for,
    session,
)

import logging

import quota_manager.sql_management as sqlm
import quota_manager.sqlite_helper_functions as sqlh
import quota_manager.quota_management as qm
import quota_manager.flask_tools.flask_utils as flu

import quota_manager.flask_tools.user_html as uhtml

user_app = Flask(__name__)
user_app.secret_key = "donbosco1815"


@user_app.after_request
def log_resp(resp):
    log.debug(
        "HTTP %s %s UA=%r -> %s",
        request.method,
        request.path,
        request.headers.get("User-Agent", ""),
        resp.status,
    )
    return resp


log = logging.getLogger(__name__)

GENERAL_ERROR_MESSAGE = {
    flu.UndefinedException: "Internal error logging in user. Please reload page.",
}


# --- Routes ---
@user_app.route("/login", methods=["GET", "POST"])
def login():

    msg = session.pop("message", "")
    error = session.pop("error", "")
    captive = session.pop("captive", False)

    log.debug(f"login: captive: {captive}")

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user_ip = request.remote_addr

        USER_LOGIN_ERROR_MESSAGES = {
            sqlh.IPAddressError: f"Login failed. IP address for user {username} could not be determined. Please disconnect from network and try again.",
            sqlm.UserNameError: f"Failed attempting to log in user {username}: User does not exist.",
            qm.RestrictedDayError: "Login not allowed today (restricted day).",
            qm.RestrictedUserError: "This device is not allowed on this network.",
            flu.UndefinedException: "Internal error logging in user. Please reload page.",
        }

        user_mac, error = flu.safe_call(
            qm.mac_from_ip,
            error,
            USER_LOGIN_ERROR_MESSAGES,
            user_ip,
        )

        if error:
            return render_template_string(uhtml.login_form, error=error)

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
            return render_template_string(uhtml.login_form, error=error)

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
                return render_template_string(uhtml.login_form, error=error)

            log.info(
                f"Login successful for {username}! User device {user_mac} at {user_ip} now has Internet access."
            )

            ua = request.headers.get("User-Agent", "")
            log.debug(ua)

            if captive:
                # Apple / Mac (non-iPhone)
                if ("Apple" in ua or "Mac" in ua) and "iPhone" not in ua:
                    log.debug(
                        f"Apple device detected for {user_mac}, returning regular page"
                    )
                    msg = (
                        f"Login successful! Device {user_mac} now has Internet access."
                    )
                    session["message"] = msg
                    return redirect(url_for("user_dashboard", username=username))

                # iPhone CNA
                elif "iPhone" in ua:
                    msg = "\nIf you are on iPhone, please press the 'cancel' button in the top right, then select 'Use Without Internet'."
                    session["message"] = msg
                    log.debug(f"iPhone CNA detected for {user_mac}, returning 200")
                    log.debug(
                        f"iPhone CNA detected for {user_mac}, directing to user dashboard"
                    )
                    redirect(url_for("user_dashboard", username=username))

                # Android CNA
                elif "Android" in ua:
                    log.debug(f"Android CNA detected for {user_mac}, returning 204")
                    log.debug(
                        f"Android CNA detected for {user_mac}, directing to user dashboard"
                    )
                    redirect(url_for("user_dashboard", username=username))

                # Other devices
                else:
                    log.debug(
                        f"Other device detected for {user_mac}, returning regular page"
                    )
                    msg = (
                        f"Login successful! Device {user_mac} now has Internet access."
                    )
                    session["message"] = msg
                    return redirect(url_for("user_dashboard", username=username))

            return redirect(url_for("user_dashboard", username=username))

        else:
            log.debug(f"Login unsuccessful. Invalid username or password")
            error += flu.error_appender(error, "Invalid username or password")
            return render_template_string(uhtml.login_form, error=error)

    return render_template_string(uhtml.login_form, message=msg, error=error)


@user_app.route("/user/<username>/dashboard", methods=["GET", "POST"])
def user_dashboard(username):

    msg = session.pop("message", "")
    error = session.pop("error", "")

    USER_DASHBOARD_ERROR_MESSAGES = {
        flu.UndefinedException: f"Internal error attempting to display usage for user {username}. Please reload page.",
    }

    logged_in, error = flu.safe_call(
        sqlm.check_if_user_logged_in,
        error,
        USER_DASHBOARD_ERROR_MESSAGES,
        username,
    )

    if not logged_in or error:
        return redirect(url_for("login"))

    # SESSION AUTHENTICATION CHECK (#6)
    if session.get("username") != username:
        return redirect(url_for("login"))

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
        uhtml.user_dashboard_template,
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

    return render_template_string(uhtml.password_change_form, error=error)


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

    error = None

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

    error = None

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

    return redirect(url_for("login"))


@user_app.route("/clients3.google.com")
@user_app.route("/connectivitycheck.gstatic.com")
@user_app.route("/connectivitycheck.android.com")
@user_app.route("/connecttest.txt")
@user_app.route("/ncsi.txt")
def windows_ncsi():
    session["captive"] = True
    user_ip = request.remote_addr

    error = None

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


@user_app.route("/ipv6.msftncsi.com")
@user_app.route("/ipv4.msftncsi.com")
@user_app.route("/www.msftncsi.com")
@user_app.route("/check_network_status.txt")
@user_app.route("/")
def linux_nm():
    username = session.get("username")
    if username:
        return redirect(url_for("user_dashboard", username=username), 302)
    session["captive"] = True
    return redirect("/login", 302)


@user_app.errorhandler(404)
def fallback(_):
    # If already authenticated, shove them to dashboard instead of bouncing to login forever
    username = session.get("username")
    if username:
        return redirect(url_for("user_dashboard", username=username), 302)

    session["captive"] = True
    return redirect("/login", 302)
