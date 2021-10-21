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
        is_simulator,
        with_pin,
        with_tcpsigner=False,
        default_port=9999,
        default_host="localhost",
        default_keyfile="key.secp256",
        default_statefile="state.json",
        default_bridge_address="0x0000000000000000000000000000000001000006",
        default_checkpoint="0xf81e265becb438e4511f5029c4ad086543ffb993a3f14bd70588f1e3cc24f5c3", # noqa E501
        default_netparams="mainnet",
        default_speed_bps=5*1024,
        default_min_cumulative_difficulty="0x1",
        default_pin_file="pin.txt",
        default_logging_config_path="logging.cfg",
        default_tcpsigner_host="localhost",
        default_tcpsigner_port=8888,
    ):
        self.description = description
        self.is_simulator = is_simulator
        self.with_pin = with_pin
        self.with_tcpsigner = with_tcpsigner
        self.default_port = default_port
        self.default_host = default_host
        self.default_keyfile = default_keyfile
        self.default_statefile = default_statefile
        self.default_pin_file = default_pin_file
        self.default_bridge_address = default_bridge_address
        self.default_checkpoint = default_checkpoint
        self.default_netparams = default_netparams
        self.default_speed_bps = default_speed_bps
        self.default_min_cumulative_difficulty = default_min_cumulative_difficulty
        self.default_logging_config_path = default_logging_config_path
        self.default_tcpsigner_port = default_tcpsigner_port
        self.default_tcpsigner_host = default_tcpsigner_host

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
        if self.is_simulator:
            parser.add_argument(
                "-k",
                "--key",
                dest="keyfile",
                help="Private key file to load. (default 'key.secp256')",
                default=self.default_keyfile,
            )
            parser.add_argument(
                "-r",
                "--bridge",
                dest="bridge_address",
                help=f"Bridge address. (default '{self.default_bridge_address}')",
                default=self.default_bridge_address,
            )
            parser.add_argument(
                "-s",
                "--state",
                dest="statefile",
                help=f"State file to load. (default '{self.default_statefile}')",
                default=self.default_statefile,
            )
            parser.add_argument(
                "-c",
                "--checkpoint",
                dest="checkpoint",
                help=f"Checkpoint state. (default '{self.default_checkpoint}')",
                default=self.default_checkpoint,
            )
            parser.add_argument(
                "-n",
                "--netparams",
                dest="netparams",
                help=f"Network parameters. (default '{self.default_netparams}'). "
                "Can also specify network parameters with a JSON string.",
                default=self.default_netparams,
            )
            parser.add_argument(
                "-d",
                "--difficulty",
                dest="min_cumulative_difficulty",
                help="Minimum cumulative difficulty. "
                f"(default '{self.default_min_cumulative_difficulty}'). "
                "Can be specified with a hex string (starting with '0x') "
                "or a decimal string.",
                default=self.default_min_cumulative_difficulty,
            )
            parser.add_argument(
                "-S",
                "--bps",
                dest="speed_bps",
                help="Simulated device processing speed in bytes "
                f"per second. (default {self.default_speed_bps} bps).",
                type=int,
                default=self.default_speed_bps,
            )
        else:
            parser.add_argument(
                "-D",
                "--dongledebug",
                dest="dongle_debug",
                action="store_true",
                help="Low level dongle debug. (defaults to no)",
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

        if self.with_tcpsigner:
            parser.add_argument(
                "-tp",
                "--tcpsigner-port",
                dest="tcpsigner_port",
                help=f"TCPSigner listening port (default {self.default_tcpsigner_port})",
                type=int,
                default=self.default_tcpsigner_port,
            )
            parser.add_argument(
                "-th",
                "--tcpsigner-host",
                dest="tcpsigner_host",
                help=f"TCPSigner host. (default '{self.default_tcpsigner_host}')",
                default=self.default_tcpsigner_host,
            )

        options = parser.parse_args()

        return options
