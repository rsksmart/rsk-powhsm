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
from pathlib import Path
import base64
from .certificate_v1 import HSMCertificate
from .utils import is_nonempty_hex_string
from sgx.envelope import SgxQuote


class HSMCertificateV2Element:
    def __init__(self):
        raise NotImplementedError("Cannot instantiate a HSMCertificateV2Element")

    @classmethod
    def from_dict(kls, element_map):
        if element_map.get("type") not in kls.TYPE_MAPPING:
            raise ValueError("Invalid or missing element type for "
                             f"element {element_map.get("name")}")

        return kls.TYPE_MAPPING[element_map["type"]](element_map)

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
        # TODO: this should yield not implemented
        # TODO: implementation should be down to each specific subclass
        return None

    def is_valid(self, certifier):
        # TODO: this should yield not implemented
        # TODO: implementation should be down to each specific subclass
        return True

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
        return self._message.hex()

    @property
    def custom_data(self):
        return self._custom_data.hex()

    @property
    def signature(self):
        return self._signature.hex()

    def get_value(self):
        return {
            "sgx_quote": SgxQuote(self._message),
            "message": self.custom_data,
        }

    def to_dict(self):
        return {
            "name": self.name,
            "type": "sgx_quote",
            "message": self.message,
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
        return self._message.hex()

    @property
    def key(self):
        return self._key.hex()

    @property
    def auth_data(self):
        return self._auth_data.hex()

    @property
    def signature(self):
        return self._signature.hex()

    def to_dict(self):
        return {
            "name": self.name,
            "type": "sgx_attestation_key",
            "message": self.message,
            "key": self.key,
            "auth_data": self.auth_data,
            "signature": self.signature,
            "signed_by": self.signed_by,
        }


class HSMCertificateV2ElementX509(HSMCertificateV2Element):
    @classmethod
    def from_pemfile(kls, pem_path, name, signed_by):
        return kls.from_pem(Path(pem_path).read_text(), name, signed_by)

    @classmethod
    def from_pem(kls, pem_str, name, signed_by):
        return kls({
            "name": name,
            "message": re.sub(r"[\s\n\r]+", " ", pem_str)
                         .replace("-----END CERTIFICATE-----", "")
                         .replace("-----BEGIN CERTIFICATE-----", "")
                         .strip().encode(),
            "signed_by": signed_by,
        })

    def __init__(self, element_map):
        self._init_with_map(element_map)

    def _init_with_map(self, element_map):
        super()._init_with_map(element_map)

        try:
            self._message = base64.b64decode(element_map.get("message"))
        except Exception:
            raise ValueError(f"Invalid message for HSM certificate element {self.name}")

    @property
    def message(self):
        return base64.b64encode(self._message).decode("ASCII")

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
