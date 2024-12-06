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

from .misc import info, head, get_hsm, AdminError, get_ud_value_for_attestation
from .unlock import do_unlock
from .certificate import HSMCertificateV2, HSMCertificateV2Element


def do_attestation(options):
    head("### -> Get powHSM attestation", fill="#")
    hsm = None

    # Require an output file
    if options.output_file_path is None:
        raise AdminError("No output file path given")

    # Get the UD value for the attestation
    info("Gathering user-defined attestation value... ", options.verbose)
    ud_value = get_ud_value_for_attestation(options.attestation_ud_source)
    info(f"Using {ud_value} as the user-defined attestation value")

    # Attempt to unlock the device
    if not options.no_unlock:
        try:
            do_unlock(options, label=False)
        except Exception as e:
            raise AdminError(f"Failed to unlock device: {str(e)}")

    # Connection
    hsm = get_hsm(options.verbose)

    # powHSM attestation
    info("Gathering powHSM attestation... ", options.verbose)
    try:
        powhsm_attestation = hsm.get_powhsm_attestation(ud_value)
    except Exception as e:
        raise AdminError(f"Failed to gather powHSM attestation: {str(e)}")
    info("powHSM attestation gathered")

    hsm.disconnect()

    # Generate and save the attestation certificate
    info("Generating the attestation certificate... ", options.verbose)

    att_cert = HSMCertificateV2()
    # TODO:
    # 1. Parse envelope
    # 2. Add actual elements of the certificate
    att_cert.add_element(HSMCertificateV2Element(powhsm_attestation))
    att_cert.save_to_jsonfile(options.output_file_path)

    info(f"Attestation certificate saved to {options.output_file_path}")
