import logging
import threading

from quota_manager.quota_management import (
    poll_ip_neigh,
    ip_timeout_updater,
    ip_timeout_enforcer,
)
from quota_manager.sql_management import IP_POLLING, IP_TIMEOUT

log = logging.getLogger(__name__)


def ip_neigh_poll_and_update(stop_event):
    while not stop_event.is_set():
        ip_addr, mac_addr, now = poll_ip_neigh()
        ip_timeout_updater(ip_addr, mac_addr, now)

        stop_event.wait(IP_POLLING)


def ip_neigh_enforcer(stop_event: threading.Event):
    while not stop_event.is_set():
        stop_event.wait(IP_TIMEOUT)
        ip_timeout_enforcer()
