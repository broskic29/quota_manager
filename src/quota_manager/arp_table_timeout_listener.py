import logging
import threading
from queue import Queue, Empty
from time import sleep
from python_arptable import get_arp_table
import datetime as dt

from quota_manager import quota_management as qm

UTC_OFFSET = 2
POLLING_INTERVAL = 30

event_queue = Queue()
log = logging.getLogger(__name__)


def arp_table_poller(stop_event: threading.Event):
    while not stop_event.is_set():
        arp_table = get_arp_table()
        for entry in arp_table:
            event_queue.put(entry)
        stop_event.wait(POLLING_INTERVAL)


def arp_table_timeout_tracking(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            entry = event_queue.get(timeout=1)  # timeout to check stop_event
        except Empty:
            continue

        try:
            mac_address = entry["HW address"]

            tz = dt.timezone(dt.timedelta(hours=UTC_OFFSET))
            timestamp = dt.datetime.now(tz)

            qm.update_arp_timeout_db(mac_address, timestamp)

        except Exception as e:
            log.error(
                f"Unexpected error updating arp timeout database for {entry}: {e}."
            )


def arp_timeout_enforcer(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            timeout_dict = qm.get_timed_out_users()
            qm.enforce_timeouts(timeout_dict)
        except Exception as e:
            log.error(f"Unexpected error enforcing arp table timeouts: {e}.")
        stop_event.wait(POLLING_INTERVAL)
