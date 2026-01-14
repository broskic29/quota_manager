import logging


class SubstringFilter(logging.Filter):
    def __init__(self, username=None, mac_addr=None, ip_addr=None):
        super().__init__()
        self.username = username
        self.mac_addr = mac_addr
        self.ip_addr = ip_addr

    def filter(self, record):
        msg = record.getMessage()  # The fully formatted log message
        if self.username and self.username not in msg:
            return False
        if self.mac_addr and self.mac_addr not in msg:
            return False
        if self.ip_addr and self.ip_addr not in msg:
            return False
        return True


def configure_logging(
    log_level: str = "INFO",
    filters=None,
    module_levels: dict | None = None,
):
    """
    Setup logging with context-aware formatter and optional filters.

    :param log_level: str, e.g., "DEBUG", "INFO"
    :param filters: dict, e.g., {"username": "test@gmail.com"}
    :param module_levels: dict, e.g., {"quota_manager.ip_neigh_timeout_listener": logging.DEBUG}
    """
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper()))

    handler = logging.StreamHandler()
    handler.setLevel(logging.NOTSET)  # Important: don’t block DEBUG here

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] "
        "%(funcName)s(), %(filename)s:%(lineno)d: "
        "%(message)s"
    )

    handler.setFormatter(formatter)

    username = filters.get("username")
    mac_addr = filters.get("mac")
    ip_addr = filters.get("ip")

    print()

    handler.addFilter(
        SubstringFilter(username=username, mac_addr=mac_addr, ip_addr=ip_addr)
    )

    # Remove any existing handlers to avoid double logging
    if logger.hasHandlers():
        logger.handlers.clear()

    logger.addHandler(handler)

    # Override per-module levels
    if module_levels:
        for mod_name, level in module_levels.items():
            logging.getLogger(mod_name).setLevel(level)

    logging.getLogger("waitress").setLevel(logging.INFO)
    logging.getLogger("pyroute2").setLevel(logging.INFO)
