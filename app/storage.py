"""Cooperative local database lock: restore excludes running Scrubbr processes."""
import fcntl
import os
from contextlib import contextmanager
from pathlib import Path


class StorageBusy(Exception):
    pass


@contextmanager
def database_lock(path, exclusive=False):
    path = Path(path).resolve()
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StorageBusy("Database is in use. Stop Scrubbr before restoring.") from None
        yield
    finally:
        os.close(fd)
