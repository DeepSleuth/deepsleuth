import os


def timezone():
    return os.environ.get("TZ", "UTC")
