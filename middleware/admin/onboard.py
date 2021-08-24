import sys
import random
from ledger.hsm2dongle import HSM2Dongle
from ledger.pin import BasePin
from .misc import info, bls, get_hsm, dispose_hsm, PIN_ERROR_MESSAGE, AdminError, ask_for_pin

def do_onboard(options):
    info("### -> Onboard")
    hsm = None

    # Validate pin (if given)
    pin = None
    if options.pin is not None:
        if not BasePin.is_valid(options.pin.encode()):
            raise AdminError(PIN_ERROR_MESSAGE)
        pin = options.pin.encode()

    # Connection
    hsm = get_hsm(options.verbose)

    # Mode check
    info("Finding mode... ", options.verbose)
    mode = hsm.get_current_mode()
    info(f"Mode: {mode.name.capitalize()}")

    # Require bootloader mode for onboarding
    if mode != HSM2Dongle.MODE.BOOTLOADER:
        raise AdminError("Device not in bootloader mode. Disconnect and re-connect the ledger and try again")

    # Echo check
    info("Sending echo... ", options.verbose)
    if not hsm.echo():
        raise AdminError("Echo error")
    info("Echo OK")

    info("Is device onboarded? ... ", options.verbose)
    is_onboarded = hsm.is_onboarded()
    info(f"Onboarded: {bls(is_onboarded)}")

    if is_onboarded:
        message = "WARNING: The following operation will wipe the device and generate a new seed. This cannot be undone."
    else:
        message = "The following operation will onboard the device."
    info("*" * len(message))
    info(message)
    info("Do you want to proceed? Yes/No")
    info("*" * len(message))
    while True:
        info("> ", False)
        sys.stdout.flush()
        answer = sys.stdin.readline().rstrip()
        if answer.lower() in ["n", "no"]:
            raise AdminError("Cancelled by user")
        if answer.lower() == "yes":
            break
        info("Please answer 'Yes' or 'No'")

    # If we get here, then it means we need to onboard

    # Ask the user for a pin if one not given
    if pin is None:
        info("Please select a pin for the device.")
        pin = ask_for_pin(require_alpha=True)

    # Generate a random seed
    info("Generating a random seed... ", options.verbose)
    seed = gen_seed()
    info("Seed generated")

    # Onboard
    info("Onboarding... ", options.verbose)
    sys.stdout.flush()
    hsm.onboard(seed, pin)
    info("Onboarded")

    message = "Onboarding done. Disconnect and re-connect the ledger before first use"
    info("*" * len(message))
    info(message)
    info("*" * len(message))

    dispose_hsm(hsm)

def gen_seed():
    random.seed()
    seed = b''
    for i in range(32):
        seed += bytes([random.randint(0,255)])
    return seed
