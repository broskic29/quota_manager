import logging
import sys


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


class MaxLevelFilter(logging.Filter):
    def __init__(self, max_level: int):
        super().__init__()
        self.max_level = max_level

    def filter(self, record):
        return record.levelno < self.max_level


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
    logger.handlers.clear()
    logger.setLevel(log_level)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] "
        "%(funcName)s(), %(filename)s:%(lineno)d: "
        "%(message)s"
    )

    h_out = logging.StreamHandler(sys.stdout)
    h_out.setLevel(logging.NOTSET)
    h_out.addFilter(MaxLevelFilter(logging.ERROR))
    h_out.setFormatter(fmt)

    h_err = logging.StreamHandler(sys.stderr)
    h_err.setLevel(logging.ERROR)
    h_err.setFormatter(fmt)

    logger.addHandler(h_out)
    logger.addHandler(h_err)

    username = filters.get("username")
    mac_addr = filters.get("mac")
    ip_addr = filters.get("ip")

    h_out.addFilter(
        SubstringFilter(username=username, mac_addr=mac_addr, ip_addr=ip_addr)
    )

    logger.addHandler(h_out)
    logger.addHandler(h_err)

    # Override per-module levels
    if module_levels:
        for mod_name, level in module_levels.items():
            logging.getLogger(mod_name).setLevel(level)

    logging.getLogger("waitress").setLevel(logging.INFO)
    logging.getLogger("pyroute2").setLevel(logging.INFO)
