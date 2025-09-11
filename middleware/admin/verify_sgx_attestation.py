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

from .misc import info, head, AdminError
from .attestation_utils import PowHsmAttestationMessage, load_pubkeys, \
                               compute_pubkeys_hash, compute_pubkeys_output, \
                               get_sgx_root_of_trust
from .x509_utils import get_intel_pcs_x509_crl
from .x509_validator import X509CertificateValidator
from .certificate import HSMCertificate, HSMCertificateV2ElementX509


# ###################################################################################
# As default root authority, we use the Provisioning Certification Root CA from Intel
# The Provisioning Certification Root CA is available for download
# from Intel, as described here:
# https://api.portal.trustedservices.intel.com/content/documentation.html

DEFAULT_ROOT_AUTHORITY = "https://certificates.trustedservices.intel.com/"\
                         "Intel_SGX_Provisioning_Certification_RootCA.pem"

# ###################################################################################


def do_verify_attestation(options):
    head("### -> Verify powHSM attestation", fill="#")

    if options.attestation_certificate_file_path is None:
        raise AdminError("No attestation certificate file given")

    if options.pubkeys_file_path is None:
        raise AdminError("No public keys file given")

    # Certificate validator with Intel SGX PCS CRL getter
    certificate_validator = X509CertificateValidator(get_intel_pcs_x509_crl)
    HSMCertificateV2ElementX509.set_certificate_validator(certificate_validator)

    # Load root authority
    root_authority = options.root_authority or DEFAULT_ROOT_AUTHORITY
    info(f"Attempting to gather root authority from {root_authority}...")
    try:
        root_of_trust = get_sgx_root_of_trust(root_authority)
        info("Attempting to validate self-signed root authority...")
        if not root_of_trust.is_valid(root_of_trust):
            raise ValueError("Failed to validate self-signed root of trust")
    except Exception as e:
        raise AdminError(f"Invalid root authority {root_authority}: {e}")
    info(f"Using {root_authority} as root authority")

    # Load public keys, compute their hash and format them for output
    try:
        pubkeys_map = load_pubkeys(options.pubkeys_file_path)
        pubkeys_hash = compute_pubkeys_hash(pubkeys_map)
        pubkeys_output = compute_pubkeys_output(pubkeys_map)
    except Exception as e:
        raise AdminError(str(e))

    # Load the given attestation key certificate
    try:
        att_cert = HSMCertificate.from_jsonfile(options.attestation_certificate_file_path)
    except Exception as e:
        raise AdminError(f"While loading the attestation certificate file: {str(e)}")

    # Validate the certificate using the given root authority
    # (this should be Intel's provisioning certification root
    # CA certificate)
    result = att_cert.validate_and_get_values(root_of_trust)

    # powHSM specific validations
    if "quote" not in result:
        raise AdminError("Certificate does not contain a powHSM attestation")

    powhsm_result = result["quote"]
    if not powhsm_result[0]:
        raise AdminError(
            f"Invalid powHSM attestation: error validating '{powhsm_result[1]}'")
    powhsm_result = powhsm_result[1]

    sgx_quote = powhsm_result["sgx_quote"]
    powhsm_message = bytes.fromhex(powhsm_result["message"])
    if not PowHsmAttestationMessage.is_header(powhsm_message):
        raise AdminError(
            f"Invalid powHSM attestation message header: {powhsm_message.hex()}")

    try:
        powhsm_message = PowHsmAttestationMessage(powhsm_message)
    except Exception as e:
        raise AdminError(f"Error parsing powHSM attestation message: {str(e)}")
    reported_pubkeys_hash = powhsm_message.public_keys_hash

    if reported_pubkeys_hash != pubkeys_hash:
        raise AdminError(
            f"powHSM attestation public keys hash mismatch: expected {pubkeys_hash.hex()}"
            f" but attestation reports {reported_pubkeys_hash.hex()}"
        )

    signer_info = [
        f"Hash: {pubkeys_hash.hex()}",
        "",
        f"Installed powHSM MRENCLAVE: {sgx_quote.report_body.mrenclave.hex()}",
        f"Installed powHSM MRSIGNER: {sgx_quote.report_body.mrsigner.hex()}",
        f"Installed powHSM version: {powhsm_message.version}",
    ]

    signer_info += [
        f"Platform: {powhsm_message.platform}",
        f"UD value: {powhsm_message.ud_value.hex()}",
        f"Best block: {powhsm_message.best_block.hex()}",
        f"Last transaction signed: {powhsm_message.last_signed_tx.hex()}",
        f"Timestamp: {powhsm_message.timestamp}",
    ]

    head(
        ["powHSM verified with public keys:"] + pubkeys_output + signer_info,
        fill="-",
    )
