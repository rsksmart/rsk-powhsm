import sys


class Color:
    OK = "\033[92m"
    FAIL = "\033[91m"
    HEADER = "\033[37;1m"
    DEBUG_L1 = "\033[38;5;247m"
    DEBUG_L2 = "\033[38;5;240m"
    END = "\033[0m"

    @classmethod
    def text(cls, color, s):
        return f"{color}{s}{cls.END}"


def info(msg, nl=False):
    sys.stdout.write(msg)
    if nl:
        sys.stdout.write("\n")
    sys.stdout.flush()


def header(msg):
    info(Color.text(Color.HEADER, f"[ {msg} ]"), nl=True)


def ok():
    info(Color.text(Color.OK, " ✔"), nl=True)


def error(msg):
    info(Color.text(Color.FAIL, f" ✗ {msg}"), nl=True)


def debug(msg):
    info(Color.text(Color.DEBUG_L1, msg), nl=True)
