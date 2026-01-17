import logging
import threading
from queue import Queue, Empty
import time
from pyroute2 import IPRoute

from pyroute2.netlink.rtnl.ndmsg import NUD_REACHABLE

from quota_manager.quota_management import ip_timeout_updater, ip_timeout_enforcer
from quota_manager.sql_management import IP_POLLING, IP_TIMEOUT

event_queue = Queue()
log = logging.getLogger(__name__)

ip = IPRoute()


def ip_neigh_poll_and_update(stop_event):
    while not stop_event.is_set():
        now = time.monotonic()  # IMPORTANT
        neighbors = ip.get_neighbours()

        for n in neighbors:

            if n["state"] & NUD_REACHABLE:
                ip_addr = dict(n.get("attrs")).get("NDA_DST")
                mac_addr = dict(n.get("attrs")).get("NDA_LLADDR")
                ip_timeout_updater(ip_addr, mac_addr, now)

        stop_event.wait(IP_POLLING)


def ip_neigh_enforcer(stop_event: threading.Event):
    while not stop_event.is_set():
        stop_event.wait(IP_TIMEOUT)
        ip_timeout_enforcer(time.monotonic())
