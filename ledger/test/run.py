import sys
from options import OptionParser
from cases import TestSuite
from ledger.hsm2dongle import HSM2Dongle
from ledger.hsm2dongle_tcp import HSM2DongleTCP
import output

import logging

logging.disable(logging.CRITICAL)

_exchange_fn = None


def debug_dongle_exchange(dongle, bs, timeout):
    sys.stdout.write("\n")
    sys.stdout.write(output.Color.DEBUG_L2)
    result = _exchange_fn(bs, timeout=timeout)
    sys.stdout.write(output.Color.END)
    return result


if __name__ == "__main__":
    options = OptionParser("Run the signer tests").parse()

    try:
        output.header("Setup")

        if options.dongle:
            dongle = HSM2Dongle(options.dongle_verbose)
            output.info("Running against a USB device", nl=True)
        else:
            dongle = HSM2DongleTCP(options.host, options.port, options.dongle_verbose)
            output.info("Running against a TCP device", nl=True)

        output.info(f"Loading test cases from {options.tests_path}")
        if options.tests_filter != "":
            output.info(f" (with filter '{options.tests_filter}')")
        suite = TestSuite.load_from_path(options.tests_path, options.tests_filter)
        suite.debug = options.verbose
        output.ok()

        output.info("Connecting to dongle")
        dongle.connect()
        output.ok()

        if options.dongle_verbose:
            _exchange_fn = dongle.dongle.exchange
            dongle.dongle.exchange = debug_dongle_exchange.__get__(
                dongle.dongle, dongle.dongle.__class__)

        output.info("Getting version")
        version = dongle.get_version()
        output.ok()
        output.info(f"Version: {version}", nl=True)

        output.header("Running tests")
        tests_passed = suite.run(dongle, version)

        output.header("Teardown")
        output.info("Disconnecting from dongle")
        dongle.disconnect()
        output.ok()
    except RuntimeError as e:
        output.error(str(e))
        sys.exit(1)

    sys.exit(0 if tests_passed else 1)
