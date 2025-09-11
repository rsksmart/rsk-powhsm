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

import re
import base64
import ecdsa
import hashlib
from datetime import datetime, UTC
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives.asymmetric import ec
from .certificate_v1 import HSMCertificate
from .utils import is_nonempty_hex_string
from .misc import info
from sgx.envelope import SgxQuote, SgxReportBody


class HSMCertificateV2Element:
    def __init__(self):
        raise NotImplementedError("Cannot instantiate a HSMCertificateV2Element")

    @classmethod
    def from_dict(cls, element_map):
        if element_map.get("type") not in cls.TYPE_MAPPING:
            raise ValueError("Invalid or missing element type for "
                             f"element {element_map.get('name')}")

        return cls.TYPE_MAPPING[element_map["type"]](element_map)

    def _init_with_map(self, element_map):
        if "name" not in element_map:
            raise ValueError("Missing name for HSM certificate element")

        self._name = element_map["name"]

        if "signed_by" not in element_map:
            raise ValueError("Missing certifier for HSM certificate element")
        self._signed_by = element_map["signed_by"]

    @property
    def name(self):
        return self._name

    @property
    def signed_by(self):
        return self._signed_by

    def get_value(self):
        raise NotImplementedError(f"{type(self).__name__} can't provide a value")

    def get_pubkey(self):
        raise NotImplementedError(f"{type(self).__name__} can't provide a public key")

    def is_valid(self, certifier):
        raise NotImplementedError(f"{type(self).__name__} can't be queried for validity")

    def get_tweak(self):
        return None


class HSMCertificateV2ElementSGXQuote(HSMCertificateV2Element):
    def __init__(self, element_map):
        self._init_with_map(element_map)

    def _init_with_map(self, element_map):
        super()._init_with_map(element_map)

        if not is_nonempty_hex_string(element_map.get("message")):
            raise ValueError(f"Invalid message for HSM certificate element {self.name}")
        self._message = bytes.fromhex(element_map["message"])

        if not is_nonempty_hex_string(element_map.get("custom_data")):
            raise ValueError("Invalid custom data for HSM certificate "
                             f"element {self.name}")
        self._custom_data = bytes.fromhex(element_map["custom_data"])

        if not is_nonempty_hex_string(element_map.get("signature")):
            raise ValueError("Invalid signature for HSM certificate element {self.name}")
        self._signature = bytes.fromhex(element_map["signature"])

    @property
    def message(self):
        return SgxQuote(self._message)

    @property
    def custom_data(self):
        return self._custom_data.hex()

    @property
    def signature(self):
        return self._signature.hex()

    def is_valid(self, certifier):
        try:
            # Validate custom data
            expected = hashlib.sha256(self._custom_data).digest()
            if expected != self.message.report_body.report_data.field[:len(expected)]:
                return False

            # Verify signature against the certifier
            return certifier.get_pubkey().verify_digest(
                self._signature,
                hashlib.sha256(self._message).digest(),
                ecdsa.util.sigdecode_der,
            )
        except Exception:
            return False

    def get_value(self):
        return {
            "sgx_quote": self.message,
            "message": self.custom_data,
        }

    def to_dict(self):
        return {
            "name": self.name,
            "type": "sgx_quote",
            "message": self._message.hex(),
            "custom_data": self.custom_data,
            "signature": self.signature,
            "signed_by": self.signed_by,
        }


class HSMCertificateV2ElementSGXAttestationKey(HSMCertificateV2Element):
    def __init__(self, element_map):
        self._init_with_map(element_map)

    def _init_with_map(self, element_map):
        super()._init_with_map(element_map)

        if not is_nonempty_hex_string(element_map.get("message")):
            raise ValueError(f"Invalid message for HSM certificate element {self.name}")
        self._message = bytes.fromhex(element_map["message"])

        if not is_nonempty_hex_string(element_map.get("key")):
            raise ValueError(f"Invalid key for HSM certificate element {self.name}")
        self._key = bytes.fromhex(element_map["key"])

        if not is_nonempty_hex_string(element_map.get("auth_data")):
            raise ValueError(f"Invalid auth data for HSM certificate element {self.name}")
        self._auth_data = bytes.fromhex(element_map["auth_data"])

        if not is_nonempty_hex_string(element_map.get("signature")):
            raise ValueError(f"Invalid signature for HSM certificate element {self.name}")
        self._signature = bytes.fromhex(element_map["signature"])

    @property
    def message(self):
        return SgxReportBody(self._message)

    @property
    def key(self):
        return ecdsa.VerifyingKey.from_string(self._key, ecdsa.NIST256p)

    @property
    def auth_data(self):
        return self._auth_data.hex()

    @property
    def signature(self):
        return self._signature.hex()

    def is_valid(self, certifier):
        try:
            # Validate report data
            expected = hashlib.sha256(self.key.to_string() + self._auth_data).digest()
            if expected != self.message.report_data.field[:len(expected)]:
                return False

            # Verify signature against the certifier
            return certifier.get_pubkey().verify_digest(
                self._signature,
                hashlib.sha256(self._message).digest(),
                ecdsa.util.sigdecode_der,
            )
        except Exception:
            return False

    def get_pubkey(self):
        return ecdsa.VerifyingKey.from_string(self._key, ecdsa.NIST256p)

    def to_dict(self):
        return {
            "name": self.name,
            "type": "sgx_attestation_key",
            "message": self.message.get_raw_data().hex(),
            "key": self.key.to_string("uncompressed").hex(),
            "auth_data": self.auth_data,
            "signature": self.signature,
            "signed_by": self.signed_by,
        }


class HSMCertificateV2ElementX509(HSMCertificateV2Element):
    HEADER_BEGIN = "-----BEGIN CERTIFICATE-----"
    HEADER_END = "-----END CERTIFICATE-----"

    _certificate_validator = None

    @classmethod
    def set_certificate_validator(cls, certificate_validator):
        cls._certificate_validator = certificate_validator

    @classmethod
    def from_pemfile(cls, pem_path, name, signed_by):
        return cls.from_pem(Path(pem_path).read_text(), name, signed_by)

    @classmethod
    def from_pem(cls, pem_str, name, signed_by):
        return cls({
            "name": name,
            "message": re.sub(r"[\s\n\r]+", " ", pem_str)
                         .replace(cls.HEADER_END, "")
                         .replace(cls.HEADER_BEGIN, "")
                         .strip().encode(),
            "signed_by": signed_by,
        })

    def __init__(self, element_map):
        self._init_with_map(element_map)
        self._certificate = None

    def _init_with_map(self, element_map):
        super()._init_with_map(element_map)

        try:
            self._message = base64.b64decode(element_map.get("message"))
        except Exception:
            raise ValueError(f"Invalid message for HSM certificate element {self.name}")

    @property
    def message(self):
        return base64.b64encode(self._message).decode("ASCII")

    @property
    def certificate(self):
        if self._certificate is None:
            self._certificate = x509.load_pem_x509_certificate((
                self.HEADER_BEGIN + self.message + self.HEADER_END).encode())
        return self._certificate

    @property
    def is_root_of_trust(self):
        return self.name == self.signed_by

    def is_valid(self, certifier):
        # IMPORTANT: for now, we only allow verifying the validity of an
        # HSMCertificateV2ElementX509 using another HSMCertificateV2ElementX509
        # instance as certifier. That way, we can simplify the validation procedure
        # by using a helper X509 validator and therefore ensure maximum use of the
        # underlying library's capabilities (cryptography).
        if not isinstance(certifier, type(self)):
            raise RuntimeError(f"Invalid certifier given for {type(self)} validation")

        # Certificate validator must be injected
        if self._certificate_validator is None:
            raise RuntimeError("Certificate validator not set")

        subject = self.certificate
        issuer = certifier.certificate
        now = datetime.now(UTC)

        result = self._certificate_validator.validate(
            subject, issuer, now, check_crl=not self.is_root_of_trust)

        if not result["valid"]:
            # TODO: find a better way of showing this
            info(f"While validating element {self.name}: {result["reason"]}")
            return False

        # TODO: find a better way of showing this
        if len(result["warnings"]) > 0:
            info("***** WARNINGS *****")
            for warning in result["warnings"]:
                info(warning)
            info("********************")

        return True

    def get_pubkey(self):
        try:
            public_key = self.certificate.public_key()

            if not isinstance(public_key.curve, ec.SECP256R1):
                raise ValueError("Certificate does not have a NIST P-256 public key")

            public_bytes = public_key.public_bytes(
                Encoding.X962, PublicFormat.CompressedPoint)

            return ecdsa.VerifyingKey.from_string(public_bytes, ecdsa.NIST256p)
        except Exception as e:
            raise ValueError(f"Error gathering public key from certificate: {str(e)}")

    def to_dict(self):
        return {
            "name": self.name,
            "type": "x509_pem",
            "message": self.message,
            "signed_by": self.signed_by,
        }


# Element type mappings
HSMCertificateV2Element.TYPE_MAPPING = {
    "sgx_quote": HSMCertificateV2ElementSGXQuote,
    "sgx_attestation_key": HSMCertificateV2ElementSGXAttestationKey,
    "x509_pem": HSMCertificateV2ElementX509,
}


class HSMCertificateV2(HSMCertificate):
    VERSION = 2
    ROOT_ELEMENT = "sgx_root"
    ELEMENT_BASE_CLASS = HSMCertificateV2Element
    ELEMENT_FACTORY = HSMCertificateV2Element.from_dict
