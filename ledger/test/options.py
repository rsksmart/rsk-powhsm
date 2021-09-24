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
