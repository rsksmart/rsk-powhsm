from ledger.hsm2dongle import HSM2Dongle
from .misc import info, bls, get_hsm, dispose_hsm, AdminError


def do_exit(options, label=True):
    if label:
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

    # Get version (this feature is version-dependent)
    version = hsm.get_version()
    info(f"Signer version: {version}")
    if version >= HSM2Dongle.MAX_VERSION_SIGNER_EXIT:
        raise AdminError(
            f"Exit command not supported from {HSM2Dongle.MAX_VERSION_SIGNER_EXIT} "
            "onwards"
        )

    # Onboard check
    info("Is device onboarded? ... ", options.verbose)
    is_onboarded = hsm.is_onboarded()
    info(f"Onboarded: {bls(is_onboarded)}")
    if not is_onboarded:
        raise AdminError("Device not onboarded")

    # Exit the app, go into menu
    info("Exiting app... ", options.verbose)
    try:
        hsm.exit_menu()
    except Exception:
        pass
    info("Exit OK")

    dispose_hsm(hsm)
