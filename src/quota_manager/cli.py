import asyncio
import logging

from .app import QuotaManagerApp


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    app = QuotaManagerApp()
    asyncio.run(app.start())
