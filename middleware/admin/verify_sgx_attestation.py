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
from .sgx_utils import get_sgx_extensions, get_tcb_info, validate_tcb_info, \
                       get_qeid_info, validate_qeid_info
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

# #######################################################################################
# SGX TCB information endpoint as per
# https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-tcb-info-v4

SGX_TCB_INFO_ENDPOINT = "https://api.trustedservices.intel.com/sgx/certification/v4/tcb"

# #######################################################################################

# #######################################################################################
# SGX QE identity information endpoint as per
# https://api.portal.trustedservices.intel.com/content/
# documentation.html#pcs-enclave-identity-v4

SGX_QE_ID_ENDPOINT = "https://api.trustedservices.intel.com/sgx/certification/v4/"\
                     "qe/identity"

# #######################################################################################


def do_verify_attestation(options):
    head("### -> Verify powHSM attestation", fill="#")

    if options.attestation_certificate_file_path is None:
        raise AdminError("No attestation certificate file given")

    if options.pubkeys_file_path is None:
        raise AdminError("No public keys file given")

    # Certificate validator with Intel SGX PCS CRL getter
    certificate_validator = X509CertificateValidator(get_intel_pcs_x509_crl)
    HSMCertificateV2ElementX509.set_certificate_validator(certificate_validator)

    # SGX extensions collateral getter
    HSMCertificateV2ElementX509.set_collateral_getter(get_sgx_extensions)

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

    if "quote" not in result:
        raise AdminError("Certificate does not contain a powHSM attestation")

    powhsm_result = result["quote"]
    if not powhsm_result["valid"]:
        raise AdminError(
            f"Invalid powHSM attestation: error "
            f"validating '{powhsm_result["failed_element"]}'")
    powhsm_collateral = powhsm_result["collateral"]
    powhsm_result = powhsm_result["value"]

    # Grab and verify TCB information
    try:
        if "quoting_enclave" not in powhsm_collateral:
            raise AdminError("Certificate does not contain PCK collateral")
        pck_collateral = powhsm_collateral["quoting_enclave"]

        tcb_info_res = get_tcb_info(
            SGX_TCB_INFO_ENDPOINT,
            pck_collateral["fmspc"],
            root_of_trust.certificate)
        tcb_info = tcb_info_res["tcb_info"]["tcbInfo"]

        tcb_validation_result = validate_tcb_info(pck_collateral, tcb_info)
        if not tcb_validation_result["valid"]:
            raise AdminError(f"TCB error: {tcb_validation_result["reason"]}")

        if len(tcb_info_res["warnings"]) > 0:
            info("***** TCB INFO WARNINGS *****")
            for w in tcb_info_res["warnings"]:
                info(w)
            info("*****************************")
    except Exception as e:
        raise AdminError(f"While trying to verify TCB information: {e}")

    # Grab and verify QE identity
    try:
        if "attestation" not in powhsm_collateral:
            raise AdminError("Certificate does not contain QE collateral")
        qe_collateral = powhsm_collateral["attestation"]

        qeid_info_res = get_qeid_info(
            SGX_QE_ID_ENDPOINT,
            root_of_trust.certificate)
        qeid_info = qeid_info_res["qeid_info"]["enclaveIdentity"]

        qeid_validation_result = validate_qeid_info(qe_collateral, qeid_info)
        if not qeid_validation_result["valid"]:
            raise AdminError(f"QE ID error: {qeid_validation_result["reason"]}")

        if len(qeid_info_res["warnings"]) > 0:
            info("***** QE ID INFO WARNINGS *****")
            for w in qeid_info_res["warnings"]:
                info(w)
            info("*****************************")
    except Exception as e:
        raise AdminError(f"While trying to verify QE ID information: {e}")

    # powHSM specific validations
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

    tcb_info = [
        f"Status: {tcb_validation_result["status"]}",
        f"Issued: {tcb_validation_result["date"]}",
        f"Advisories: {", ".join(tcb_validation_result["advisories"]) or "None"}",
        f"TCB evaluation data number: {tcb_validation_result["edn"]}",
        "SVNs:"
    ]

    tcb_info += map(lambda svn: f"  - {svn}", tcb_validation_result["svns"])

    qeid_info = [
        f"Status: {qeid_validation_result["status"]}",
        f"Issued: {qeid_validation_result["date"]}",
        f"Advisories: {", ".join(qeid_validation_result["advisories"]) or "None"}",
        f"TCB evaluation data number: {qeid_validation_result["edn"]}",
        f"ISVSVN: {qeid_validation_result["isvsvn"]}",
    ]

    head(
        ["powHSM verified with public keys:"] + pubkeys_output + signer_info,
        fill="-",
    )

    head(
        ["TCB Information:"] + tcb_info,
        fill="-",
    )

    head(
        ["QE Identity Information:"] + qeid_info,
        fill="-",
    )
