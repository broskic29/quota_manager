import argparse
import logging

from .app import QuotaManagerApp
from quota_manager.logging_config import configure_logging


def parse_args():
    parser = argparse.ArgumentParser(description="Quota Manager CLI")
    parser.add_argument(
        "-l", "--log-level", default="INFO", help="Global logging level"
    )
    parser.add_argument("--username", help="Filter username")
    parser.add_argument("--mac", help="Filter MAC address")
    parser.add_argument("--ip", help="Filter IP address")

    # Example per-subsystem debug flag
    parser.add_argument(
        "--debug-ip-neigh",
        action="store_true",
        help="Enable IP neigh tracking subsystem debug logging",
    )
    parser.add_argument(
        "--debug-flask-user-login",
        action="store_true",
        help="",
    )
    parser.add_argument(
        "--debug-flask-admin",
        action="store_true",
        help="",
    )
    parser.add_argument(
        "--debug-sql-management",
        action="store_true",
        help="",
    )
    parser.add_argument(
        "--debug-quota-management",
        action="store_true",
        help="",
    )
    parser.add_argument(
        "--debug-nftables-management",
        action="store_true",
        help="",
    )
    parser.add_argument(
        "--debug-usage-tracking",
        action="store_true",
        help="",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # Set filters
    filters = {}
    if args.username:
        filters["username"] = args.username
    if args.mac:
        filters["mac"] = args.mac
    if args.ip:
        filters["ip"] = args.ip

    # Module-specific log levels
    module_levels = {}
    if args.debug_ip_neigh:
        module_levels["quota_manager.ip_neigh_timeout_listener"] = logging.DEBUG
    if args.debug_flask_user_login:
        module_levels["quota_manager.user_login_flask_server"] = logging.DEBUG
    if args.debug_flask_admin:
        module_levels["quota_manager.admin_management_flask_server"] = logging.DEBUG
    if args.debug_sql_management:
        module_levels["quota_manager.sql_management"] = logging.DEBUG
    if args.debug_quota_management:
        module_levels["quota_manager.quota_management"] = logging.DEBUG
    if args.debug_nftables_management:
        module_levels["quota_manager.nftables_management"] = logging.DEBUG
    if args.debug_usage_tracking:
        module_levels["quota_manager.usage_tracker"] = logging.DEBUG

    # Configure logging
    configure_logging(
        log_level=args.log_level, filters=filters, module_levels=module_levels
    )

    app = QuotaManagerApp()
    app.start()
