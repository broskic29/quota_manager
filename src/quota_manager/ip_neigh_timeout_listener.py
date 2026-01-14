import logging
import threading
from queue import Queue, Empty
from time import sleep
from pyroute2 import IPRoute

from pyroute2.netlink.rtnl.ndmsg import (
    NUD_INCOMPLETE,
    NUD_REACHABLE,
    NUD_STALE,
    NUD_DELAY,
    NUD_PROBE,
    NUD_FAILED,
    NUD_NOARP,
    NUD_PERMANENT,
)

from quota_manager import quota_management as qm
from quota_manager.sql_management import IP_TIMEOUT

UTC_OFFSET = 2
POLLING_INTERVAL = 10

event_queue = Queue()
log = logging.getLogger(__name__)

ip = IPRoute()


def ip_neigh_poller(stop_event: threading.Event):
    while not stop_event.is_set():
        neighbors = ip.get_neighbours()
        for neighbor in neighbors:
            event_queue.put(neighbor)
        stop_event.wait(POLLING_INTERVAL)


def ip_neigh_timeout_tracking(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            n = event_queue.get(timeout=1)  # timeout to check stop_event
        except Empty:
            continue

        try:
            # log.debug(f"Arp table entry: {entry}")
            if n["state"] & NUD_REACHABLE:
                ip_addr = dict(n.get("attrs")).get("NDA_DST")
                mac_addr = dict(n.get("attrs")).get("NDA_LLADDR")

                qm.ip_timeout_updater(ip_addr, mac_addr)

        except Exception as e:
            log.error(f"Unexpected error updating ip timeout database for {n}: {e}.")


def ip_neigh_enforcer(stop_event: threading.Event):
    while not stop_event.is_set():
        qm.ip_timeout_enforcer()
        stop_event.wait(IP_TIMEOUT)
