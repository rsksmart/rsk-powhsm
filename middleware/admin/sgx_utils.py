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

import json
import requests
import ecdsa
from datetime import datetime, UTC
from hashlib import sha256
from cryptography import x509
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from pyasn1.codec.der import decoder
from pyasn1.type.univ import SequenceOf, Integer, OctetString
from urllib.parse import unquote as url_unquote
from .x509_utils import split_pem_certificates, get_intel_pcs_x509_crl
from .x509_validator import X509CertificateValidator


def _parse_asn1_extensions(extension, base_oid, spec):
    def assert_type(id, v, t):
        if not isinstance(v, t):
            raise RuntimeError(f"Expected for element {id} to be a {t} "
                               f"but found a {type(v)} instead")

    oid = str(extension[0])
    if base_oid != oid:
        raise RuntimeError(f"Expected finding extension with OID {base_oid} but "
                           f"found {oid} instead")

    value = extension[1]
    if isinstance(spec, list) or spec["type"] == "seq":
        assert_type(base_oid, value, SequenceOf)
        if isinstance(spec, list):
            items = spec
        else:
            items = spec["items"]
        result = {}
        for index, item in enumerate(items):
            xt = value[index]
            item_oid = f"{base_oid}{item["oid"]}"
            result[item["name"]] = _parse_asn1_extensions(xt, item_oid, item)
        return result

    if spec["type"] == "seq":
        assert_type(base_oid, value, SequenceOf)

    if spec["type"] == "bytes":
        assert_type(base_oid, value, OctetString)
        return bytes(value).hex()

    if spec["type"] == "int":
        assert_type(base_oid, value, Integer)
        return int(value)

    raise RuntimeError(f"Unknown spec type {spec["type"]}")


def get_sgx_extensions(certificate):
    BASE_OID = "1.2.840.113741.1.13.1"
    SGX_EXTENSIONS_SPEC = [
        {"oid": ".1", "name": "ppid", "type": "bytes"},
        {"oid": ".2", "name": "tcb", "type": "seq", "items": [
            {"oid": ".1", "name": "comp01", "type": "int"},
            {"oid": ".2", "name": "comp02", "type": "int"},
            {"oid": ".3", "name": "comp03", "type": "int"},
            {"oid": ".4", "name": "comp04", "type": "int"},
            {"oid": ".5", "name": "comp05", "type": "int"},
            {"oid": ".6", "name": "comp06", "type": "int"},
            {"oid": ".7", "name": "comp07", "type": "int"},
            {"oid": ".8", "name": "comp08", "type": "int"},
            {"oid": ".9", "name": "comp09", "type": "int"},
            {"oid": ".10", "name": "comp10", "type": "int"},
            {"oid": ".11", "name": "comp11", "type": "int"},
            {"oid": ".12", "name": "comp12", "type": "int"},
            {"oid": ".13", "name": "comp13", "type": "int"},
            {"oid": ".14", "name": "comp14", "type": "int"},
            {"oid": ".15", "name": "comp15", "type": "int"},
            {"oid": ".16", "name": "comp16", "type": "int"},
            {"oid": ".17", "name": "pcesvn", "type": "int"},
            {"oid": ".18", "name": "cpusvn", "type": "bytes"},
        ]},
        {"oid": ".3", "name": "pceid", "type": "bytes"},
        {"oid": ".4", "name": "fmspc", "type": "bytes"},
    ]

    try:
        oid = x509.ObjectIdentifier(BASE_OID)
        extensions = certificate.extensions.get_extension_for_oid(oid)
        extensions = [
            extensions.value.oid.dotted_string,
            list(decoder.decode(extensions.value.value))[0]
        ]
        return _parse_asn1_extensions(extensions, BASE_OID, SGX_EXTENSIONS_SPEC)
    except x509.extensions.ExtensionNotFound:
        return None


def get_tcb_info(url, fmspc_hex, root_of_trust, update="early"):
    try:
        final_url = f"{url}?fmspc={fmspc_hex}&update={update}"
        tcb_res = requests.get(final_url)
        if tcb_res.status_code != 200:
            raise RuntimeError(f"Server replied with status {tcb_res.status_code}")

        warnings = []

        # Parse TCB info
        ctype = tcb_res.headers["Content-Type"]
        if ctype != "application/json":
            raise RuntimeError(f"Unknown content-type: {ctype}")
        tcb_info = json.loads(tcb_res.text)

        warning = tcb_res.headers.get("warning")
        if warning is not None:
            warning = f"Getting {final_url}: {warning}"
            warnings.append(warning)

        # Parse certification chain
        issuer_chain = tcb_res.headers.get("TCB-Info-Issuer-Chain")
        if issuer_chain is None:
            raise RuntimeError("No issuer certification chain in response")

        issuer_chain = split_pem_certificates(url_unquote(issuer_chain))
        issuer_chain = list(map(
            lambda pem: x509.load_pem_x509_certificate(pem.encode()), issuer_chain))

        if len(issuer_chain) < 2:
            raise RuntimeError("Expected at least two certificates "
                               "in the TCB info issuer chain")

        # Check root of trust is same as expected
        ic_root = issuer_chain[-1]
        if root_of_trust != ic_root:
            raise RuntimeError(f"Root of trust ({root_of_trust.subject}) does not "
                               f"match root of TCB info issuer chain: {ic_root.subject}")

        # Validate certification chain in root to leaf order
        validator = X509CertificateValidator(get_intel_pcs_x509_crl)
        now = datetime.now(UTC)
        issuer = ic_root
        for subject in reversed(issuer_chain[:-1]):
            result = validator.validate(subject, issuer, now)
            if not result["valid"]:
                raise RuntimeError("Error validating TCB info issuer "
                                   f"chain: {result["reason"]}")
            warnings += result["warnings"]
            issuer = subject

        # Validate TCB info signature
        issuer = issuer_chain[0]
        digest = sha256(json.dumps(
            tcb_info["tcbInfo"], indent=None, separators=(",", ":")).encode()).digest()
        pubkey = ecdsa.VerifyingKey.from_string(issuer.public_key().public_bytes(
                Encoding.X962, PublicFormat.CompressedPoint), ecdsa.NIST256p)
        pubkey.verify_digest(
            bytes.fromhex(tcb_info["signature"]),
            digest,
            sigdecode=ecdsa.util.sigdecode_string
        )

        return {
            "tcb_info": tcb_info,
            "warnings": warnings,
        }
    except Exception as e:
        raise RuntimeError(f"While fetching TCB info from {final_url}: {e}")


def validate_tcb_info(pck_info, tcb_info):
    try:
        matching_level = None
        for level in tcb_info["tcbLevels"]:
            found = True
            svns_info = []
            for index, component in enumerate(level["tcb"]["sgxtcbcomponents"]):
                comp_id = f"comp{index+1:02}"
                pck_svn = pck_info["tcb"][comp_id]
                tcb_svn = component["svn"]
                if pck_svn < tcb_svn:
                    found = False
                    break
                svns_info.append(f"Comp {index+1:02}: {pck_svn} >= {tcb_svn}")

            if not found:
                continue

            pck_pcesvn = pck_info["tcb"]["pcesvn"]
            tcb_pcesvn = level["tcb"]["pcesvn"]
            if pck_pcesvn >= tcb_pcesvn:
                svns_info.append(f"PCESVN: {pck_pcesvn} >= {tcb_pcesvn}")
                matching_level = level
                break

        if matching_level is None:
            return {
                "valid": False,
                "reason": "TCB level is unsupported"
            }

        return {
            "valid": True,
            "status": matching_level["tcbStatus"],
            "date": matching_level["tcbDate"],
            "advisories": matching_level["advisoryIDs"],
            "svns": svns_info,
            "edn": tcb_info["tcbEvaluationDataNumber"],
        }
    except Exception as e:
        return {
            "valid": False,
            "reason": f"While validating TCB information: {e}",
        }
