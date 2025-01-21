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
from argparse import ArgumentParser
import logging
from ledger.hsm2dongle import HSM2DongleError
from comm.platform import Platform
from admin.misc import not_implemented, info, AdminError, DEFAULT_ATT_UD_SOURCE
from admin.unlock import do_unlock
from admin.onboard import do_onboard
from admin.pubkeys import do_get_pubkeys
from admin.changepin import do_changepin
from admin.sgx_attestation import do_attestation
from admin.verify_sgx_attestation import do_verify_attestation


def main():
    logging.disable(logging.CRITICAL)

    actions = {
        "unlock": do_unlock,
        "onboard": do_onboard,
        "pubkeys": do_get_pubkeys,
        "changepin": do_changepin,
        "attestation": do_attestation,
        "verify_attestation": do_verify_attestation,
    }

    parser = ArgumentParser(description="SGX powHSM Administrative tool")
    parser.add_argument("operation", choices=list(actions.keys()))
    parser.add_argument(
        "-p",
        "--port",
        dest="sgx_port",
        help="SGX powHSM listening port (default 7777)",
        type=int,
        default=7777,
    )
    parser.add_argument(
        "-s",
        "--host",
        dest="sgx_host",
        help="SGX powHSM host. (default 'localhost')",
        default="localhost",
    )
    parser.add_argument("-P", "--pin", dest="pin", help="PIN.")
    parser.add_argument(
        "-n",
        "--newpin",
        dest="new_pin",
        help="New PIN (only valid for 'changepin' operation).",
    )
    parser.add_argument(
        "-a",
        "--anypin",
        dest="any_pin",
        action="store_const",
        help="Allow any pin (only valid for 'changepin' operation).",
        default=False,
        const=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file_path",
        help="Output file (only valid for 'onboard', 'pubkeys' and 'attestation' "
        "operations).",
    )
    parser.add_argument(
        "-u",
        "--nounlock",
        dest="no_unlock",
        action="store_const",
        help="Do not attempt to unlock (only valid for 'changepin' and 'pubkeys' "
        "operations).",
        default=False,
        const=True,
    )
    parser.add_argument(
        "--attudsource",
        dest="attestation_ud_source",
        default=DEFAULT_ATT_UD_SOURCE,
        help="JSON-RPC endpoint used to retrieve the latest RSK block hash used "
        "as the user defined value for the attestation (defaults to "
        f"{DEFAULT_ATT_UD_SOURCE}). Can also specify a 32-byte hex string to use as"
        " the value.",
    )
    parser.add_argument(
        "-t",
        "--attcert",
        dest="attestation_certificate_file_path",
        help="Attestation key certificate file (only valid for "
        "'verify_attestation' operation).",
    )
    parser.add_argument(
        "-r",
        "--root",
        dest="root_authority",
        help="Root attestation authority (only valid for 'verify_attestation' "
        "operation). Defaults to Intel SGX's root authority.",
    )
    parser.add_argument(
        "-b",
        "--pubkeys",
        dest="pubkeys_file_path",
        help="Public keys file (only valid for 'verify_attestation' operation).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_const",
        help="Enable verbose mode",
        default=False,
        const=True,
    )

    try:
        options = parser.parse_args()
        Platform.set(Platform.SGX, {
            "sgx_host": options.sgx_host,
            "sgx_port": options.sgx_port,
        })
        actions.get(options.operation, not_implemented)(options)
        sys.exit(0)
    except AdminError as e:
        info(str(e))
        sys.exit(1)
    except HSM2DongleError as e:
        info(str(e))
        sys.exit(2)
    except KeyboardInterrupt:
        info("Interrupted by user!")
        sys.exit(3)
    except Exception as e:
        info(str(e))
        sys.exit(4)


if __name__ == "__main__":
    main()
