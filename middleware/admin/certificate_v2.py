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

from .certificate_v1 import HSMCertificate


class HSMCertificateV2Element:
    pass


class HSMCertificateV2ElementSGXQuote(HSMCertificateV2Element):
    def __init__(self, name, message, custom_data, signature, signed_by):
        self.name = name
        self.message = message
        self.custom_data = custom_data
        self.signature = signature
        self.signed_by = signed_by

    def to_dict(self):
        return {
            "name": self.name,
            "type": "sgx_quote",
            "message": self.message.hex(),
            "custom_data": self.custom_data.hex(),
            "signature": self.signature.hex(),
            "signed_by": self.signed_by,
        }


class HSMCertificateV2ElementSGXAttestationKey(HSMCertificateV2Element):
    def __init__(self, name, message, key, auth_data, signature, signed_by):
        self.name = name
        self.message = message
        self.key = key
        self.auth_data = auth_data
        self.signature = signature
        self.signed_by = signed_by

    def to_dict(self):
        return {
            "name": self.name,
            "type": "sgx_attestation_key",
            "message": self.message.hex(),
            "key": self.key.hex(),
            "auth_data": self.auth_data.hex(),
            "signature": self.signature.hex(),
            "signed_by": self.signed_by,
        }


class HSMCertificateV2ElementX509(HSMCertificateV2Element):
    def __init__(self, name, message, signed_by):
        self.name = name
        self.message = message
        self.signed_by = signed_by

    def to_dict(self):
        return {
            "name": self.name,
            "type": "x509_pem",
            "message": self.message.decode('ASCII'),
            "signed_by": self.signed_by,
        }


class HSMCertificateV2(HSMCertificate):
    VERSION = 2
    ELEMENT_BASE_CLASS = HSMCertificateV2Element

    def validate_and_get_values(self, raw_root_pubkey_hex):
        # TODO
        pass

    def _parse(self, certificate_map):
        # TODO
        pass
