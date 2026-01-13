import logging
import threading
from queue import Queue, Empty
from time import sleep
from python_arptable import get_arp_table

from quota_manager import quota_management as qm
from quota_manager.sql_management import ARP_TIMEOUT

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
            # log.debug(f"Arp table entry: {entry}")

            mac_address = entry["HW address"]
            qm.arp_timeout_updater(mac_address)

        except Exception as e:
            log.error(
                f"Unexpected error updating arp timeout database for {entry}: {e}."
            )


def arp_table_enforcer(stop_event: threading.Event):
    while not stop_event.is_set():

        qm.arp_timeout_enforcer()
        stop_event.wait(ARP_TIMEOUT)
