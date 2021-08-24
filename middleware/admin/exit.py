from ledger.hsm2dongle import HSM2Dongle
from .misc import info, bls, get_hsm, dispose_hsm, AdminError

def do_exit(options):
    info("### -> Exit")
    # Connection
    hsm = None
    hsm = get_hsm(options.verbose)

    # Mode check
    info("Finding mode... ", options.verbose)
    mode = hsm.get_current_mode()
    info(f"Mode: {mode.name.capitalize()}")

    # Mode
    if mode != HSM2Dongle.MODE.APP:
        raise AdminError("Device not in App mode")

    # Onboard check
    info("Is device onboarded? ... ", options.verbose)
    is_onboarded = hsm.is_onboarded()
    info(f"Onboarded: {bls(is_onboarded)}")
    if not is_onboarded:
        raise AdminError("Device not onboarded")

    # Exit the app, go into menu
    info("Exiting app... ", options.verbose)
    try: hsm.exit_menu()
    except: pass
    info("Exit OK")

    dispose_hsm(hsm)
