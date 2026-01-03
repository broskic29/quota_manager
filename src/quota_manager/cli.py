import argparse
import asyncio
import logging

from .app import QuotaManagerApp


def parse_args():
    parser = argparse.ArgumentParser(
        prog="quota_manager",
        description="Quota Manager service",
    )

    parser.add_argument(
        "-l",
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set log level (default: INFO)",
    )

    return parser.parse_args()


def configure_logging(log_level: str):
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def main():
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    app = QuotaManagerApp()
    asyncio.run(app.start())
