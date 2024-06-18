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

from argparse import ArgumentParser


class OptionParser:
    def __init__(
        self,
        description,
        default_tests_path="./resources",
        default_port=8888,
        default_host="localhost",
    ):
        self.description = description
        self.default_tests_path = default_tests_path
        self.default_port = default_port
        self.default_host = default_host

    def parse(self):
        parser = ArgumentParser(description=self.description)

        parser.add_argument(
            "-d",
            "--dongle",
            dest="dongle",
            action="store_true",
            default=False,
            help="Run with a physical dongle (defaults to no)",
        )
        parser.add_argument(
            "-r",
            "--resources",
            dest="tests_path",
            default=self.default_tests_path,
            help=f"Tests path (default '{self.default_tests_path}')",
        )
        parser.add_argument(
            "-f",
            "--filter",
            dest="tests_filter",
            default="",
            help="Tests filter (comma-separated list of filename prefixes)",
        )
        parser.add_argument(
            "-p",
            "--port",
            dest="port",
            type=int,
            default=self.default_port,
            help=f"Listening port (default {self.default_port})",
        )
        parser.add_argument(
            "-b",
            "--bind",
            dest="host",
            default=self.default_host,
            help=f"IP to bind to (default '{self.default_host}')",
        )
        parser.add_argument(
            "-P",
            "--pin",
            dest="pin",
            help="Device pin (only used for -d option)",
        )
        parser.add_argument(
            "-m",
            "--manual-unlock",
            dest="manual_unlock",
            action="store_true",
            default=False,
            help="Perform device unlock manually (defaults to no)",
        )
        parser.add_argument(
            "-v",
            "--verbose",
            dest="verbose",
            action="store_true",
            default=False,
            help="Verbose mode (defaults to no)",
        )
        parser.add_argument(
            "-w",
            "--dongle-verbose",
            dest="dongle_verbose",
            action="store_true",
            default=False,
            help="Dongle exchange verbose mode (defaults to no)",
        )

        options = parser.parse_args()

        return options
