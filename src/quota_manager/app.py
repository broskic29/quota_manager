import threading
import logging
from waitress import serve
from queue import Queue
from time import sleep

from quota_manager.usage_tracker import start_usage_tracking
from quota_manager.quota_management import log_out_all_users
from quota_manager.sql_management import init_freeradius_db, init_usage_db
from quota_manager.flask_tools.user_login_flask_server import user_app
from quota_manager.flask_tools.admin_management_flask_server import admin_management_app
from quota_manager.ip_neigh_timeout_listener import (
    ip_neigh_poll_and_update,
    ip_neigh_enforcer,
)

log = logging.getLogger(__name__)

logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("asyncio.selector_events").setLevel(logging.WARNING)


class QuotaManagerApp:
    """
    Lifecycle:
      - start(): initialize, spawn worker threads + servers, then block until stop_event is set
      - stop(): request shutdown + join worker threads + final cleanup
    """

    def __init__(self):
        self.stop_event = threading.Event()
        self.event_queue = Queue()
        self.threads: list[threading.Thread] = []

        self._started = False
        self._stopped = False

    def start(self) -> None:
        if self._started:
            log.warning("QuotaManagerApp.start() called more than once; ignoring.")
            return
        self._started = True

        log.info("Starting quota manager")

        init_freeradius_db()
        init_usage_db()

        self._start_flask_servers()
        self._start_usage_tracking()
        self._start_ip_neigh_threads()

        # optional: you were doing this on startup
        log_out_all_users()

        try:
            # Block until stop requested (signal handler sets stop_event).
            # wait() wakes immediately on shutdown instead of sleeping out a full interval.
            while not self.stop_event.wait(1):
                pass
        finally:
            # This guarantees cleanup runs on SIGTERM/SIGINT and on unexpected exceptions.
            self.stop()

    def _start_flask_servers(self) -> None:
        log.info("Starting login page")
        login_thread = threading.Thread(
            target=serve,
            name="waitress-login",
            kwargs={"app": user_app, "host": "0.0.0.0", "port": 5000},
            daemon=True,
        )

        log.info("Starting admin page")
        admin_thread = threading.Thread(
            target=serve,
            name="waitress-admin",
            kwargs={"app": admin_management_app, "host": "0.0.0.0", "port": 5001},
            daemon=True,
        )

        login_thread.start()
        admin_thread.start()
        log.info("Servers started on ports 5000 and 5001 (daemon threads)")

        # We don't add these to self.threads because Waitress' serve() doesn't provide a clean stop hook.
        # As daemon threads, they exit when the process exits.

    def _start_ip_neigh_threads(self) -> None:
        t_poll = threading.Thread(
            target=ip_neigh_poll_and_update,
            args=(self.stop_event,),
            name="ip-neigh-poll",
            daemon=True,
        )
        t_enf = threading.Thread(
            target=ip_neigh_enforcer,
            args=(self.stop_event,),
            name="ip-neigh-enforcer",
            daemon=True,
        )

        self.threads.extend([t_poll, t_enf])

        t_poll.start()
        t_enf.start()
        log.info("Started IP neigh tracking threads.")

    def _start_usage_tracking(self) -> None:
        usage_threads = start_usage_tracking(self.stop_event)
        # Give names if the factory didn’t
        for i, t in enumerate(usage_threads):
            if not getattr(t, "name", None) or t.name.startswith("Thread-"):
                t.name = f"usage-tracker-{i}"
        self.threads.extend(usage_threads)

        for t in usage_threads:
            t.start()

        log.info("Usage tracking started.")

    def stop(self):
        log.info("Stopping Quota Manager...")

        try:
            log_out_all_users()
        except Exception:
            log.exception("Error while logging out users during shutdown")

        # Stop ARP threads
        self.stop_event.set()
        for t in self.threads:
            if isinstance(t, threading.Thread):
                if t.is_alive():
                    t.join(timeout=5)
            else:
                log.warning(f"Non-thread in self.threads: {type(t)!r} -> {t!r}")

        still_alive = [
            t.name
            for t in self.threads
            if isinstance(t, threading.Thread) and t.is_alive()
        ]
        if still_alive:
            log.warning(
                "Threads still alive after stop (continuing shutdown): %s", still_alive
            )
        else:
            log.info("All worker threads stopped.")

        log.info("All threads stopped.")
