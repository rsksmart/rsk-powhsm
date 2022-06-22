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
import hmac
import secp256k1 as ec
import hashlib
from .utils import is_nonempty_hex_string


class HSMCertificate:
    VERSION = 1  # Only supported version
    ROOT_ELEMENT = "root"

    @staticmethod
    def from_jsonfile(path):
        try:
            with open(path, "r") as file:
                certificate_map = json.loads(file.read())

            if type(certificate_map) != dict:
                raise ValueError(
                    "JSON file must contain an object as a top level element")

            return HSMCertificate(certificate_map)
        except (ValueError, json.JSONDecodeError) as e:
            raise ValueError('Unable to read HSM certificate from "%s": %s' %
                             (path, str(e)))

    def __init__(self, certificate_map=None):
        self._targets = []
        self._elements = {}

        if certificate_map is not None:
            self._parse(certificate_map)

    def validate_and_get_values(self, raw_root_pubkey_hex):
        # Parse the root public key
        try:
            root_pubkey = ec.PublicKey(bytes.fromhex(raw_root_pubkey_hex), raw=True)
        except Exception:
            return dict([(target, (False, self.ROOT_ELEMENT))
                         for target in self._targets])

        result = {}
        for target in self._targets:
            # Build the chain from the target to the root
            chain = []
            current = self._elements[target]
            while True:
                if current.signed_by == self.ROOT_ELEMENT:
                    break
                chain.append(current)
                current = self._elements[current.signed_by]

            # Validate the chain from root to leaf
            # If valid, return True and the value of the leaf
            # If not valid, return False and the name of the element that
            # failed the validation
            current_pubkey = root_pubkey
            while True:
                # Validate this element
                if not current.is_valid(current_pubkey):
                    result[target] = (False, current.name)
                    break
                # Reached the leaf? => valid!
                if len(chain) == 0:
                    result[target] = (True, current.get_value(), current.tweak)
                    break

                current_pubkey = ec.PublicKey(bytes.fromhex(current.get_value()),
                                              raw=True)
                current = chain.pop()

        return result

    def add_element(self, element):
        if type(element) != HSMCertificateElement:
            raise ValueError(
                f"Expected an HSMCertificateElement but got a {type(element)}")
        self._elements[element.name] = element

    def clear_targets(self):
        self._targets = []

    def add_target(self, target):
        if target not in self._elements:
            raise ValueError(f"Target {target} not in elements")
        self._targets.append(target)

    def to_dict(self):
        return {
            "version": self.VERSION,
            "targets": self._targets,
            "elements": list(map(lambda e: e.to_dict(), self._elements.values())),
        }

    def save_to_jsonfile(self, path):
        with open(path, "w") as file:
            file.write("%s\n" % json.dumps(self.to_dict(), indent=2))

    def _parse(self, certificate_map):
        if "version" not in certificate_map or certificate_map["version"] != self.VERSION:
            raise ValueError(
                "Invalid or unsupported HSM certificate version "
                f"(current version is {self.VERSION})"
            )

        if "targets" not in certificate_map or type(certificate_map["targets"]) != list:
            raise ValueError("Missing or invalid targets")

        self._targets = certificate_map["targets"]

        if "elements" not in certificate_map:
            raise ValueError("Missing elements")

        for item in certificate_map["elements"]:
            element = HSMCertificateElement(item)
            self._elements[item["name"]] = element

        # Sanity: check each target has a path to the root authority
        for target in self._targets:
            if target not in self._elements:
                raise ValueError(f"Target {target} not in elements")

            visited = []
            current = self._elements[target]
            while True:
                if current.name in visited:
                    raise ValueError(
                        f"Target {target} has not got a path to the root authority")
                if current.signed_by == self.ROOT_ELEMENT:
                    break
                if current.signed_by not in self._elements:
                    raise ValueError(f"Signer {current.signed_by} not in elements")
                visited.append(current.name)
                current = self._elements[current.signed_by]


class HSMCertificateElement:
    VALID_NAMES = ["device", "attestation", "ui", "signer"]
    EXTRACTORS = {
        "device": lambda b: b[-65:],
        "attestation": lambda b: b[1:],
        "ui": lambda b: b[:],
        "signer": lambda b: b[:],
    }

    def __init__(self, element_map):
        if ("name" not in element_map
                or element_map["name"] not in self.VALID_NAMES):
            raise ValueError("Missing or invalid name for HSM certificate element")
        self._name = element_map["name"]

        if "signed_by" not in element_map:
            raise ValueError("Missing certifier for HSM certificate element")
        self._signed_by = element_map["signed_by"]

        self._tweak = None
        if "tweak" in element_map:
            if not is_nonempty_hex_string(element_map["tweak"]):
                raise ValueError(
                    f"Invalid signer tweak for HSM certificate element {self.name}")
            self._tweak = element_map["tweak"]

        if "message" not in element_map or not is_nonempty_hex_string(
                element_map["message"]):
            raise ValueError(
                f"Missing or invalid message for HSM certificate element {self.name}")
        self._message = element_map["message"]

        if "signature" not in element_map or not is_nonempty_hex_string(
                element_map["signature"]):
            raise ValueError(
                f"Missing or invalid signature for HSM certificate element {self.name}")
        self._signature = element_map["signature"]

    @property
    def name(self):
        return self._name

    @property
    def signed_by(self):
        return self._signed_by

    @property
    def tweak(self):
        return self._tweak

    @property
    def message(self):
        return self._message

    @property
    def signature(self):
        return self._signature

    def to_dict(self):
        result = {
            "name": self.name,
            "message": self.message,
            "signature": self.signature,
            "signed_by": self.signed_by,
        }

        if self.tweak is not None:
            result["tweak"] = self.tweak

        return result

    def is_valid(self, certifier_pubkey):
        try:
            message = bytes.fromhex(self.message)

            verifier_pubkey = certifier_pubkey
            if self.tweak is not None:
                tweak = hmac.new(
                    bytes.fromhex(self.tweak),
                    certifier_pubkey.serialize(compressed=False),
                    hashlib.sha256,
                ).digest()

                verifier_pubkey = verifier_pubkey.tweak_add(tweak)

            return verifier_pubkey.ecdsa_verify(
                message, verifier_pubkey.ecdsa_deserialize(bytes.fromhex(self.signature)))
        except Exception:
            return False

    def get_value(self):
        return self.EXTRACTORS[self.name](bytes.fromhex(self.message)).hex()
