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

from .misc import info, head, get_hsm, dispose_hsm, AdminError, wait_for_reconnection, \
                  get_ud_value_for_attestation
from .unlock import do_unlock
from .certificate import HSMCertificate, HSMCertificateElement


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

    # Get the UD value for the attestations
    info("Gathering user-defined attestation value... ", options.verbose)
    ud_value = get_ud_value_for_attestation(options.attestation_ud_source)
    info(f"Using {ud_value} as the user-defined attestation value")

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
        ui_attestation = hsm.get_ui_attestation(ud_value)
    except Exception as e:
        raise AdminError(f"Failed to gather UI attestation: {str(e)}")
    info("UI attestation gathered")

    # Exit the UI and reconnect
    info("Exiting UI... ", options.verbose)
    try:
        hsm.exit_menu()
    except Exception:
        # exit_menu() always throws due to USB disconnection. we don't care
        pass
    info("Exit OK")
    dispose_hsm(hsm)
    wait_for_reconnection()
    hsm = get_hsm(options.verbose)

    # Signer attestation
    info("Gathering Signer attestation... ", options.verbose)
    try:
        powhsm_attestation = hsm.get_powhsm_attestation(ud_value)
        # Health check: message and envelope must be the same
        if powhsm_attestation["message"] != powhsm_attestation["envelope"]:
            raise AdminError("Signer attestation message and envelope differ")
    except Exception as e:
        raise AdminError(f"Failed to gather Signer attestation: {str(e)}")
    info("Signer attestation gathered")

    # Augment and save the attestation certificate
    info("Generating the attestation certificate... ", options.verbose)

    att_cert.add_element(
        HSMCertificateElement({
            "name": "ui",
            "message": ui_attestation["message"],
            "signature": ui_attestation["signature"],
            "signed_by": "attestation",
            "tweak": ui_attestation["app_hash"],
        }))
    att_cert.add_element(
        HSMCertificateElement({
            "name": "signer",
            "message": powhsm_attestation["message"],
            "signature": powhsm_attestation["signature"],
            "signed_by": "attestation",
            "tweak": powhsm_attestation["app_hash"],
        }))
    att_cert.clear_targets()
    att_cert.add_target("ui")
    att_cert.add_target("signer")
    att_cert.save_to_jsonfile(options.output_file_path)

    info(f"Attestation certificate saved to {options.output_file_path}")
