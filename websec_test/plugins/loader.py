import logging

logger = logging.getLogger(__name__)


def discover_first_party() -> None:
    logger.info("discover_first_party: not yet active")


def discover_entry_points() -> None:
    logger.info("discover_entry_points: not yet active")


def discover_all() -> None:
    discover_first_party()
    discover_entry_points()
