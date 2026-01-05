import asyncio
import threading
import logging
from waitress import serve

from quota_manager.usage_tracker import daemon
from quota_manager.sql_management import init_freeradius_db, init_usage_db
from .quota_management import initialize_nftables_sets
from quota_manager.user_login_flask_server import user_login_app
from quota_manager.admin_management_flask_server import admin_management_app
from quota_manager.disconnect_listener import wifi_listener
from quota_manager.disconnect_listener import process_disconnect


log = logging.getLogger(__name__)


class QuotaManagerApp:
    def __init__(self):
        self.tasks: list[asyncio.Task] = []
        self.shutdown_event = asyncio.Event()

    async def start(self):
        log.info("Starting quota manager")

        init_freeradius_db()
        init_usage_db()

        initialize_nftables_sets()

        self.tasks.append(asyncio.create_task(self._run_daemon()))

        threading.Thread(target=self._run_login_page, daemon=True).start()
        threading.Thread(target=self._run_admin_page, daemon=True).start()

        stop_event = threading.Event()
        threading.Thread(target=wifi_listener, args=(stop_event,), daemon=True).start()
        threading.Thread(
            target=process_disconnect, args=(stop_event,), daemon=True
        ).start()

        await self.shutdown_event.wait()
        await self.stop()

    async def _run_daemon(self):
        try:
            log.info("Usage daemon started")
            await daemon()
        except asyncio.CancelledError:
            log.info("Usage daemon cancelled")

    def _run_login_page(self):
        # Flask is blocking; this is intentional
        log.info("Starting login page")
        serve(user_login_app, host="0.0.0.0", port=5000)

    def _run_admin_page(self):
        # Flask is blocking; this is intentional
        log.info("Starting admin page")
        serve(admin_management_app, host="0.0.0.0", port=5001)

    async def stop(self):
        log.info("Shutting down quota manager")

        for task in self.tasks:
            task.cancel()

        await asyncio.gather(*self.tasks, return_exceptions=True)
