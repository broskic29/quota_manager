import threading
import logging
from waitress import serve
from queue import Queue
from time import sleep

from quota_manager.usage_tracker import start_usage_tracking
from quota_manager.sql_management import init_freeradius_db, init_usage_db
from .quota_management import initialize_nftables_sets
from quota_manager.user_login_flask_server import user_login_app
from quota_manager.admin_management_flask_server import admin_management_app
from quota_manager.ip_neigh_timeout_listener import (
    ip_neigh_poller,
    ip_neigh_timeout_tracking,
    ip_neigh_enforcer,
)

log = logging.getLogger(__name__)


class QuotaManagerApp:
    def __init__(self):
        self.stop_event = threading.Event()
        self.event_queue = Queue()
        self.threads: list[threading.Thread] = []

    def start(self):
        log.info("Starting quota manager")

        init_freeradius_db()
        init_usage_db()
        initialize_nftables_sets()

        self._start_flask_servers()
        self._start_usage_tracking()
        self._start_ip_neigh_threads()

        try:
            while not self.stop_event.is_set():
                sleep(1)
        except KeyboardInterrupt:
            log.info("Keyboard interrupt received, shutting down...")
            self.stop()

    def _start_flask_servers(self):
        log.info("Starting login page")
        login_thread = threading.Thread(
            target=lambda: serve(user_login_app, host="0.0.0.0", port=5000),
            daemon=True,
        )

        log.info("Starting admin page")
        admin_thread = threading.Thread(
            target=lambda: serve(admin_management_app, host="0.0.0.0", port=5001),
            daemon=True,
        )

        login_thread.start()
        admin_thread.start()
        log.info("Flask servers started on ports 5000 and 5001")

    def _start_ip_neigh_threads(self):
        self.arp_threads = [
            threading.Thread(
                target=ip_neigh_poller, args=(self.stop_event,), daemon=True
            ),
            threading.Thread(
                target=ip_neigh_timeout_tracking, args=(self.stop_event,), daemon=True
            ),
            threading.Thread(
                target=ip_neigh_enforcer, args=(self.stop_event,), daemon=True
            ),
        ]

        self.threads.extend(self.arp_threads)

        for t in self.arp_threads:
            t.start()
        log.info("Started IP neigh tracking threads...")

    def _start_usage_tracking(self):
        usage_tracking_threads = start_usage_tracking(self.stop_event)
        self.threads.append(usage_tracking_threads)
        for t in usage_tracking_threads:
            t.start()
        log.info("Usage tracking started.")

    def stop(self):
        log.info("Stopping Quota Manager...")

        # Stop ARP threads
        self.stop_event.set()
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=5)

        log.info("All threads stopped.")
