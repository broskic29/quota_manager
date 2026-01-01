from flask import Flask, request, render_template_string, redirect, Response
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest, AccessAccept

import socket
import logging

import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm

user_login_app = Flask(__name__)
log = logging.getLogger(__name__)

LOCALHOST = "127.0.0.1"

# FreeRADIUS configuration
RADIUS_SERVER = LOCALHOST
RADIUS_SECRET = b"BrFb+sewC8wGFb8+gD2UW3Fjf583PqoE"
RADIUS_PORT = 1812

DEFAULT_SERVICE_TYPE = "Login-User"

# Logged-in users with expiration
active_sessions = {}  # {ip: expiration_time}
SESSION_TIMEOUT = 3600  # seconds (1 hour)

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


# --- FreeRADIUS authentication ---
def authenticate_radius(username, password, ip_address, mac_address):
    srv = Client(
        server=RADIUS_SERVER,
        secret=RADIUS_SECRET,
        dict=Dictionary("/etc/freeradius3/dictionary"),
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
            log.info("RADIUS: User {username} successfully authenticated.")
            return True
    except socket.timeout:
        log.info("RADIUS: User {username} failed to authenticate.")
        return False


# --- Routes ---
@user_login_app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user_ip = request.remote_addr

        try:
            user_mac = qm.mac_from_ip(user_ip)
        except KeyError:
            log.warning(f"No MAC address could be found for user {username}.")
            error = "Login failed. User MAC address could not be determined. Please disconnect from network and try again."
            return render_template_string(login_form, error=error)

        if authenticate_radius(username, password, user_ip, user_mac):

            try:
                old_user_mac = sqlm.fetch_user_mac_address_usage(username)
            except KeyError:
                old_user_mac = None

            json_message = sqlm.login_user_usage(username, user_mac, user_ip)

            qm.mac_update(old_user_mac, user_mac, username)

            log.info(
                f"Login successful for {username}! User device {user_mac} at {user_ip} now has Internet access."
            )

            ua = request.headers.get("User-Agent", "")
            log.info(ua)
            if "Apple" in ua or "Mac" in ua or "iPhone" in ua:
                # Apple CNA: return 200 Success to close portal
                return Response("Success", status=200, mimetype="text/html")
            elif "Android" in ua:
                # Android CNA: redirect 204
                return redirect("/generate_204")
            else:
                # Normal browser: show success page
                return render_template_string(
                    "<h3>Login successful!</h3><p>Device {{ mac }} now has Internet access.</p>",
                    mac=user_mac,
                )
        else:
            log.info(f"Login unsuccessful. Invalid username or password")
            error = "Invalid username or password"
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
            f"User {username} authenticated. Loggin in device at {user_mac}/{user_ip}..."
        )
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
