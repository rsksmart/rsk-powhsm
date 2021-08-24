import ecdsa
import time
from ledger.hsm2dongle import HSM2Dongle
from .misc import info, bls, get_hsm, dispose_hsm, AdminError
from .unlock import do_unlock
from comm.bip32 import BIP32Path

SIGNER_WAIT_TIME = 1 #second

PATHS = {
    "btc": BIP32Path("m/44'/0'/0'/0/0"),
    "rsk": BIP32Path("m/44'/137'/0'/0/0"),
    "mst": BIP32Path("m/44'/137'/0'/0/1"),
    "tbtc": BIP32Path("m/44'/1'/0'/0/0"),
    "trsk": BIP32Path("m/44'/1'/0'/0/1"),
    "tmst": BIP32Path("m/44'/1'/0'/0/2"),
}

def do_get_pubkeys(options):
    info("### -> Get public keys")
    hsm = None

    # Attempt to unlock and open the signing app
    if not options.no_unlock:
        try:
            do_unlock(options, label=False)
        except Exception as e:
            raise AdminError(f"Failed to unlock device: {str(e)}")

    # Wait for the signer
    time.sleep(SIGNER_WAIT_TIME)

    # Connection
    hsm = get_hsm(options.verbose)

    # Mode check
    info("Finding mode... ", options.verbose)
    mode = hsm.get_current_mode()
    info(f"Mode: {mode.name.capitalize()}")

    # Modes for which we can't get the public keys
    if mode in [HSM2Dongle.MODE.UNKNOWN, HSM2Dongle.MODE.BOOTLOADER]:
        raise AdminError("Device not in app mode. Disconnect and re-connect the ledger and try again")

    # Gather public keys
    pubkeys = {}
    for path_name in PATHS:
        info(f"Getting public key for path '{path_name}'... ", options.verbose)
        path = PATHS[path_name]
        pubkeys[path_name] = hsm.get_public_key(path)
        info("OK")

    try:
        output_file = None
        if options.output_file_path is not None:
            output_file = open(options.output_file_path, "w")
            do_output = lambda s: output_file.write(f"{s}\n")
        else:
            do_output = lambda s: info(s)

        do_output("*" * 80)
        do_output("Name \t\t Path \t\t\t\t Pubkey")
        do_output("==== \t\t ==== \t\t\t\t ======")
        for path_name in PATHS:
            path = PATHS[path_name]
            # Compress public key
            pk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkeys[path_name]), curve=ecdsa.SECP256k1)
            pubkey = pk.to_string("compressed").hex()
            do_output(f"{path_name} \t\t {path} \t\t {pubkey}")
        do_output("*" * 80)

        if output_file is not None:
            output_file.close()
            info(f"Public keys saved to {options.output_file_path}")
    except Exception as e:
        raise AdminError(f"Error writing output: {str(e)}")

    dispose_hsm(hsm)
