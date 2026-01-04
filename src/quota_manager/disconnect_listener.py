import subprocess
import json
import logging
import threading
from queue import Queue, Empty

from quota_manager import quota_management as qm
from quota_manager import sql_management as sqlm

event_queue = Queue()
log = logging.getLogger(__name__)


def wifi_listener(stop_event: threading.Event):
    """Listen for Wi-Fi events from ubus and put them into the queue."""
    try:
        proc = subprocess.Popen(
            ["ubus", "listen", "hostapd.*"],
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        while not stop_event.is_set():
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break  # subprocess ended
                continue
            try:
                event_queue.put(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue

    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait()


def process_disconnect(stop_event: threading.Event):
    """Process events from the queue and log out users on disconnect."""
    while not stop_event.is_set():
        try:
            event = event_queue.get(timeout=1)  # timeout to check stop_event
        except Empty:
            continue

        try:
            event = event_queue.get()
            evt = next(iter(event.values()))
            mac_address = evt.get("addr")
            event_type = evt.get("event")

            if event_type == "AP-STA-DISCONNECTED":
                username = sqlm.get_username_from_mac_address_usage(mac_address)
                if username:
                    qm.log_out_user(username, mac_address)
        except Exception as e:
            log.error(
                f"Unexpected error logging out user from mac address {mac_address}: {e}"
            )
