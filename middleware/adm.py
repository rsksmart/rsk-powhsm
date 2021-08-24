import sys
from argparse import ArgumentParser
import logging
from ledger.hsm2dongle import HSM2DongleError
from admin.misc import not_implemented, info, AdminError
from admin.unlock import do_unlock
from admin.onboard import do_onboard
from admin.pubkeys import do_get_pubkeys
from admin.exit import do_exit
from admin.changepin import do_changepin

DEFAULT_PIN_FILE = "pin.txt"
DEFAULT_PIN_CHANGE_FILE = "changePIN"

if __name__ == '__main__':
    logging.disable(logging.CRITICAL)

    actions = {
        'unlock': do_unlock,
        'onboard': do_onboard,
        'pubkeys': do_get_pubkeys,
        'exit': do_exit,
        'changepin': do_changepin,
    }

    parser = ArgumentParser(description="HSM 2 Administrative tool")
    parser.add_argument('operation', choices=list(actions.keys()))
    parser.add_argument("-p","--pin", dest="pin", \
                        help=f"PIN.")
    parser.add_argument("-n","--newpin", dest="new_pin", \
                        help=f"New PIN (only valid for 'changepin' operation).")
    parser.add_argument("-a","--anypin", dest="any_pin", action="store_const", \
                        help="Allow any pin (only valid for 'changepin' operation).", \
                        default=False, const=True)
    parser.add_argument("-o","--output", dest="output_file_path", \
                        help=f"Output file (only valid for 'pubkeys' operation).")
    parser.add_argument("-u","--nounlock", dest="no_unlock", action="store_const", \
                        help=f"Do not attempt to unlock (only valid for 'changepin' and 'pubkeys' operation).", \
                        default=False, const=True)
    parser.add_argument("-v","--verbose", dest="verbose", action="store_const", \
                        help="Enable verbose mode", default=False, const=True)
    options = parser.parse_args()

    try:
        actions.get(options.operation, not_implemented)(options)
        sys.exit(0)
    except AdminError as e:
        info(str(e))
        sys.exit(1)
    except HSM2DongleError as e:
        info(str(e))
        sys.exit(2)
    except KeyboardInterrupt as e:
        info("Interrupted by user!")
        sys.exit(3)
    except Exception as e:
        info(str(e))
        sys.exit(4)
