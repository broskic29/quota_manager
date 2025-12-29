from flask import Flask, request, render_template_string
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest, AccessAccept
from python_arptable import get_arp_table

import socket
import threading
import time

import quota_manager.sql_management as sqlm
import quota_manager.nftables_management as nftm

user_login_app = Flask(__name__)

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


def mac_from_ip(ip):
    arp_table = get_arp_table()
    for entry in arp_table:
        if entry["IP address"] == ip:
            return entry["HW address"]
    return None


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
        return reply.code == AccessAccept
    except socket.timeout:
        return False


# --- Session cleanup thread ---
def cleanup_sessions():
    while True:
        now = time.time()
        for mac_address in list(active_sessions.keys()):
            if active_sessions[mac_address] < now:
                # Remove nftables rule for expired user
                nftm.delete_user_from_set(mac_address)
                del active_sessions[mac_address]
        time.sleep(60)


threading.Thread(target=cleanup_sessions, daemon=True).start()


# --- Routes ---
@user_login_app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user_ip = request.remote_addr
        user_mac = mac_from_ip(user_ip)
        if authenticate_radius(username, password, user_ip, user_mac):

            old_user_mac = sqlm.fetch_user_mac(username)

            json_message = sqlm.login_user_usage(username, user_mac, user_ip)

            # if user has dynamic mac, remove old one from set
            if old_user_mac != user_mac:
                nftm.delete_user_from_set(
                    nftm.TABLE_FAMILY,
                    nftm.CAPTIVE_TABLE_NAME,
                    nftm.AUTH_SET_NAME,
                    old_user_mac,
                )

            # Add nftables rule to switch this mac to authorized set
            nftm.delete_user_from_set(
                nftm.TABLE_FAMILY, nftm.CAPTIVE_TABLE_NAME, nftm.AUTH_SET_NAME, user_mac
            )

            # Record session expiration
            active_sessions[user_mac] = time.time() + SESSION_TIMEOUT
            return f"<h3>Login successful!</h3><p>User device {user_mac} at {user_ip} now has Internet access.</p>"
        else:
            error = "Invalid username or password"
    return render_template_string(login_form, error=error)
