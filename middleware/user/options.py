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


class UserOptionParser:
    def __init__(
        self,
        description,
        with_pin,
        with_tcpconn=False,
        host_name="",
        default_port=9999,
        default_host="localhost",
        default_pin_file="pin.txt",
        default_logging_config_path="logging.cfg",
        default_tcpconn_host="localhost",
        default_tcpconn_port=8888,
    ):
        self.description = description
        self.with_pin = with_pin
        self.with_tcpconn = with_tcpconn
        self.host_name = host_name
        self.default_port = default_port
        self.default_host = default_host
        self.default_pin_file = default_pin_file
        self.default_logging_config_path = default_logging_config_path
        self.default_tcpconn_port = default_tcpconn_port
        self.default_tcpconn_host = default_tcpconn_host

    def parse(self):
        parser = ArgumentParser(description=self.description)
        parser.add_argument(
            "-p",
            "--port",
            dest="port",
            help=f"Listening port (default {self.default_port})",
            type=int,
            default=self.default_port,
        )
        parser.add_argument(
            "-b",
            "--bind",
            dest="host",
            help=f"IP to bind to. (default '{self.default_host}')",
            default=self.default_host,
        )
        parser.add_argument(
            "-D",
            "--iodebug",
            dest="io_debug",
            action="store_true",
            help="Low level I/O debug. (defaults to no)",
        )

        if self.with_pin:
            parser.add_argument(
                "-P",
                "--pin",
                dest="pin_file",
                help=f"PIN file. (default '{self.default_pin_file}')",
                default=self.default_pin_file,
            )
            parser.add_argument(
                "-X",
                "--changepin",
                dest="force_pin_change",
                action="store_true",
                help="Force PIN change. (defaults to no)",
            )

        parser.add_argument(
            "-l",
            "--logconfig",
            dest="logconfigfilepath",
            help="Logging configuration file. "
            f"(default '{self.default_logging_config_path}')",
            default=self.default_logging_config_path,
        )
        parser.add_argument(
            "--version-one",
            dest="version_one",
            action="store_true",
            help="Run in version 1 mode. (defaults to no)",
        )

        if self.with_tcpconn:
            parser.add_argument(
                f"-{self.host_name.lower()[0]}p",
                f"--{self.host_name.lower()}-port",
                dest="tcpconn_port",
                help=f"{self.host_name} listening port (default "
                     f"{self.default_tcpconn_port})",
                type=int,
                default=self.default_tcpconn_port,
            )
            parser.add_argument(
                f"-{self.host_name.lower()[0]}h",
                f"--{self.host_name.lower()}-host",
                dest="tcpconn_host",
                help=f"{self.host_name} host. (default '{self.default_tcpconn_host}')",
                default=self.default_tcpconn_host,
            )

        options = parser.parse_args()

        return options
