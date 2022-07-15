# The MIT License (MIT)
#
# Copyright (c) 2021 RSK Labs Ltd
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys


class Color:
    OK = "\033[92m"
    FAIL = "\033[91m"
    HEADER = "\033[37;1m"
    DEBUG_L1 = "\033[38;5;247m"
    DEBUG_L2 = "\033[38;5;240m"
    PROMPT_USER = "\033[95;1m"
    WARN = "\033[33;1m"
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


def skipped():
    info(Color.text(Color.WARN, " ◇"), nl=True)


def prompt_user(msg, wait_confirm=False):
    info('', nl=True)
    info(Color.text(Color.PROMPT_USER, msg), nl=True)
    if wait_confirm:
        input(Color.text(Color.PROMPT_USER, "Press [Enter] to continue"))
