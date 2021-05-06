from ledger.hsm2dongle import HSM2Dongle
from .misc import info, head, get_hsm, dispose_hsm, AdminError, wait_for_reconnection
from .utils import is_nonempty_hex_string, is_hex_string_of_length, normalize_hex_string
from .dongle_admin import DongleAdmin
from .unlock import do_unlock
from .exit import do_exit
from .certificate import HSMCertificate, HSMCertificateElement
from .rsk_client import RskClient, RskClientError

UD_VALUE_LENGTH = 32

def do_attestation(options):
    head("### -> Get UI and Signer attestations", fill="#")
    hsm = None

    # Require an output file
    if options.output_file_path is None:
        raise AdminError("No output file path given")

    # Load the given attestation key certificate
    if options.attestation_certificate_file_path is None:
        raise AdminError("No attestation certificate file given")

    try:
        att_cert = HSMCertificate.from_jsonfile(options.attestation_certificate_file_path)
    except Exception as e:
        raise AdminError(f"While loading the attestation certificate file: {str(e)}")

    # Validate the CA fields
    if options.ca is None:
        raise AdminError("No CA info given")

    ca_fields = options.ca.split(":")
    if len(ca_fields) != 3:
        raise AdminError("Invalid CA info given")
    
    ca_pubkey = ca_fields[0]
    if not is_nonempty_hex_string(ca_pubkey):
        raise AdminError("Invalid CA public key given")

    ca_hash = ca_fields[1]
    if not is_nonempty_hex_string(ca_hash):
        raise AdminError("Invalid CA hash given")

    ca_signature = ca_fields[2]
    if not is_nonempty_hex_string(ca_signature):
        raise AdminError("Invalid CA signature given")

    # Get the UD value for the UI attestation
    if is_hex_string_of_length(options.attestation_ud_source, UD_VALUE_LENGTH, allow_prefix=True):
        ud_value = normalize_hex_string(options.attestation_ud_source)
    else:
        try:
            rsk_client = RskClient(options.attestation_ud_source)
            best_block = rsk_client.get_block_by_number(rsk_client.get_best_block_number())
            ud_value = best_block["hash"][2:]
            if not is_hex_string_of_length(ud_value, UD_VALUE_LENGTH):
                raise ValueError(f"Got invalid best block from RSK server: {ud_value}")
        except RskClientError as e:
            raise AdminError(f"While fetching the best RSK block hash: {str(e)}")

    info(f"Using {ud_value} as the user-defined UI attestation value")

    # Attempt to unlock the device without exiting the UI
    try:
        do_unlock(options, label=False, exit=False)
    except Exception as e:
        raise AdminError(f"Failed to unlock device: {str(e)}")

    # Connection
    hsm = get_hsm(options.verbose)

    # UI Attestation
    info("Gathering UI attestation... ", options.verbose)
    try:
        ui_attestation = hsm.get_ui_attestation(ud_value, ca_pubkey, ca_hash, ca_signature)
    except Exception as e:
        raise AdminError(f"Failed to gather UI attestation: {str(e)}")
    info("UI attestation gathered")

    # Exit the UI and reconnect
    info("Exiting UI... ", options.verbose)
    try: hsm.exit_menu()
    except: pass
    info("Exit OK")
    dispose_hsm(hsm)
    wait_for_reconnection()
    hsm = get_hsm(options.verbose)

    # Signer attestation
    info("Gathering Signer attestation... ", options.verbose)
    try:
        signer_attestation = hsm.get_signer_attestation()
    except Exception as e:
        raise AdminError(f"Failed to gather Signer attestation: {str(e)}")
    info("Signer attestation gathered")

    # Augment and save the attestation certificate
    info("Generating the attestation certificate... ", options.verbose)

    att_cert.add_element(HSMCertificateElement({
        "name": "ui",
        "message": ui_attestation["message"],
        "extract": ":",
        "digest": HSMCertificateElement.DIGEST.NONE,
        "signature": ui_attestation["signature"],
        "signed_by": "attestation",
        "tweak": ui_attestation["app_hash"],
    }))
    att_cert.add_element(HSMCertificateElement({
        "name": "signer",
        "message": signer_attestation["message"],
        "extract": ":",
        "digest": HSMCertificateElement.DIGEST.NONE,
        "signature": signer_attestation["signature"],
        "signed_by": "attestation",
        "tweak": signer_attestation["app_hash"],
    }))
    att_cert.clear_targets()
    att_cert.add_target("ui")
    att_cert.add_target("signer")
    att_cert.save_to_jsonfile(options.output_file_path)

    info(f"Attestation certificate saved to {options.output_file_path}")
