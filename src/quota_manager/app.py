import asyncio
import signal
import logging

from .usage_tracker import daemon
from .sql_management import init_freeradius_db, init_usage_db
from .user_login_flask_server import user_login_app

log = logging.getLogger(__name__)


class QuotaManagerApp:
    def __init__(self):
        self.tasks: list[asyncio.Task] = []
        self.shutdown_event = asyncio.Event()

    async def start(self):
        log.info("Starting quota manager")

        init_freeradius_db()
        init_usage_db()

        self.tasks.append(asyncio.create_task(self._run_daemon()))

        self._run_flask()

        await self.shutdown_event.wait()
        await self.stop()

    async def _run_daemon(self):
        try:
            await daemon()
        except asyncio.CancelledError:
            log.info("Usage daemon cancelled")

    def _run_flask(self):
        # Flask is blocking; this is intentional
        user_login_app.run(host="0.0.0.0", port=5000, debug=False)

    async def stop(self):
        log.info("Shutting down quota manager")

        for task in self.tasks:
            task.cancel()

        await asyncio.gather(*self.tasks, return_exceptions=True)
