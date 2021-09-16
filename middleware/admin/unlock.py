from ledger.hsm2dongle import HSM2Dongle
from ledger.pin import BasePin
from .misc import (
    info,
    head,
    bls,
    get_hsm,
    dispose_hsm,
    PIN_ERROR_MESSAGE_ANYCHARS,
    AdminError,
    ask_for_pin,
)


def do_unlock(options, exit=True, no_exec=False, label=True):
    if label:
        head("### -> Unlock", fill="#")

    hsm = None

    # Validate pin (if given)
    pin = None
    if options.pin is not None:
        if not BasePin.is_valid(options.pin.encode(), require_alpha=False):
            raise AdminError(PIN_ERROR_MESSAGE_ANYCHARS)
        pin = options.pin.encode()

    # Connection
    hsm = get_hsm(options.verbose)

    # Mode check
    info("Finding mode... ", options.verbose)
    mode = hsm.get_current_mode()
    info(f"Mode: {mode.name.capitalize()}")

    # Onboard check
    if mode in [HSM2Dongle.MODE.BOOTLOADER, HSM2Dongle.MODE.APP]:
        info("Is device onboarded? ... ", options.verbose)
        is_onboarded = hsm.is_onboarded()
        info(f"Onboarded: {bls(is_onboarded)}")
        if not is_onboarded:
            raise AdminError("Device not onboarded")

    # Modes for which we can't unlock
    if mode == HSM2Dongle.MODE.UNKNOWN:
        raise AdminError("Device mode unknown. Already unlocked? Otherwise disconnect "
                         "and re-connect the ledger and try again")
    if mode == HSM2Dongle.MODE.APP:
        raise AdminError("Device already unlocked and in app mode")

    # Echo check
    info("Sending echo... ", options.verbose)
    if not hsm.echo():
        raise AdminError("Echo error")
    info("Echo OK")

    # Ask the user for a pin if one not given
    if pin is None:
        info("Please enter the pin.")
        pin = ask_for_pin(require_alpha=False)

    # Unlock device with PIN
    info("Unlocking with PIN... ", options.verbose)
    if not hsm.unlock(pin):
        raise AdminError("Unable to unlock: PIN mismatch")
    info("PIN accepted")

    # Exit the bootloader, go into menu (or, if app is properly signed, into
    # the app)
    if exit:
        autoexec = not (options.no_exec or no_exec)
        info(f"Exiting to menu/app (execute signer: {bls(autoexec)})... ",
             options.verbose)
        try:
            hsm.exit_menu(autoexec=autoexec)
        except Exception:
            pass
        info("Exit OK")

    dispose_hsm(hsm)
