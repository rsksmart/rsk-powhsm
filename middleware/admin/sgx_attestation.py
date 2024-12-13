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

import ecdsa
from .misc import info, head, get_hsm, AdminError, get_ud_value_for_attestation
from .unlock import do_unlock
from sgx.envelope import SgxEnvelope
from .certificate import HSMCertificateV2, HSMCertificateV2ElementSGXQuote, \
                         HSMCertificateV2ElementSGXAttestationKey, \
                         HSMCertificateV2ElementX509


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

    # Parse envelope
    info("Parsing the powHSM attestation envelope...")
    try:
        envelope = SgxEnvelope(
            bytes.fromhex(powhsm_attestation["envelope"]),
            bytes.fromhex(powhsm_attestation["message"]))
    except Exception as e:
        raise AdminError(f"SGX envelope parse error: {str(e)}")

    # Conversions
    quote_signature = ecdsa.util.sigdecode_string(
        envelope.quote_auth_data.signature.r +
        envelope.quote_auth_data.signature.s,
        ecdsa.NIST256p.order)
    quote_signature = ecdsa.util.sigencode_der(
        quote_signature[0],
        quote_signature[1],
        ecdsa.NIST256p.order)
    att_key = ecdsa.VerifyingKey.from_string(
        envelope.quote_auth_data.attestation_key.x +
        envelope.quote_auth_data.attestation_key.y,
        ecdsa.NIST256p)
    qe_rb_signature = ecdsa.util.sigdecode_string(
        envelope.quote_auth_data.qe_report_body_signature.r +
        envelope.quote_auth_data.qe_report_body_signature.s,
        ecdsa.NIST256p.order)
    qe_rb_signature = ecdsa.util.sigencode_der(
        qe_rb_signature[0],
        qe_rb_signature[1],
        ecdsa.NIST256p.order)

    # Generate and save the attestation certificate
    info("Generating the attestation certificate... ", options.verbose)
    att_cert = HSMCertificateV2()

    att_cert.add_element(
        HSMCertificateV2ElementSGXQuote(
            name="quote",
            message=envelope.quote.get_raw_data(),
            custom_data=envelope.custom_message,
            signature=quote_signature,
            signed_by="attestation",
        ))
    att_cert.add_element(
        HSMCertificateV2ElementSGXAttestationKey(
            name="attestation",
            message=envelope.quote_auth_data.qe_report_body.get_raw_data(),
            key=att_key.to_string("uncompressed"),
            auth_data=envelope.qe_auth_data.data,
            signature=qe_rb_signature,
            signed_by="quoting_enclave",
        ))
    att_cert.add_element(
        HSMCertificateV2ElementX509(
            name="quoting_enclave",
            message=envelope.qe_cert_data.certs[0],
            signed_by="platform_ca",
        ))
    att_cert.add_element(
        HSMCertificateV2ElementX509(
            name="platform_ca",
            message=envelope.qe_cert_data.certs[1],
            signed_by="sgx_root",
        ))

    att_cert.add_target("quote")
    att_cert.save_to_jsonfile(options.output_file_path)

    info(f"Attestation certificate saved to {options.output_file_path}")
