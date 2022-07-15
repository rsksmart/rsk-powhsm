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
from options import OptionParser
from cases import TestSuite, TestCase
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
        run_args = {}

        if options.dongle:
            if not options.manual_unlock and options.pin is None:
                raise RuntimeError("Auto unlock requires 'pin' argument")

            dongle = HSM2Dongle(options.dongle_verbose)
            run_on = TestCase.RUN_ON_VALUE_DONGLE
            run_args[TestCase.RUN_ARGS_MANUAL_KEY] = options.manual_unlock
            run_args[TestCase.RUN_ARGS_PIN_KEY] = options.pin
            output.info("Running against a USB device", nl=True)
        else:
            dongle = HSM2DongleTCP(options.host, options.port, options.dongle_verbose)
            run_on = TestCase.RUN_ON_VALUE_TCPSIGNER
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
        tests_passed = suite.run(dongle, run_on, run_args)
        stats = suite.get_stats()
        output.info(
            f"( {stats['passed']} passed, {stats['failed']} failed, "
            f"{stats['skipped']} skipped )", nl=True
        )

        output.header("Teardown")
        output.info("Disconnecting from dongle")
        dongle.disconnect()
        output.ok()
    except RuntimeError as e:
        output.error(str(e))
        sys.exit(1)

    sys.exit(0 if tests_passed else 1)
