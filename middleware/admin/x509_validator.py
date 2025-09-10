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

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec


class X509CertificateValidator:
    def __init__(self, crl_getter):
        self._crl_getter = crl_getter

    def get_crl_info(self, subject):
        crl_getter = self._crl_getter
        crl_info = None

        try:
            crldps = subject.extensions.\
                get_extension_for_class(x509.CRLDistributionPoints).value

            if len(crldps) == 0:
                raise RuntimeError("No CRL distribution points found in certificate")

            for crldp in crldps:
                url = crldp.full_name[0].value
                try:
                    crl_info = crl_getter(url)
                    break
                except RuntimeError:
                    pass

            if crl_info is None:
                raise RuntimeError("None of the distribution points "
                                   "provided a valid CRL")

            return crl_info
        except Exception as e:
            raise RuntimeError(f"Unable to fetch CRL for X509 certificate: {e}")

    def validate(self, subject, issuer, now, check_crl=True):
        try:
            if not isinstance(subject, x509.Certificate) or \
               not isinstance(issuer, x509.Certificate):
                raise RuntimeError("Both subject and issuer must be "
                                   "instances of x509.Certificate")

            warnings = []

            # 1. Check validity period
            if subject.not_valid_before_utc > now or subject.not_valid_after_utc < now:
                raise RuntimeError(f"{subject.subject} not within validity period")

            # 2. Verify directly issued by issuer and
            # also manually verify the signature just to
            # have a second opinion XD
            try:
                subject.verify_directly_issued_by(issuer)

                issuer.public_key().verify(
                    subject.signature,
                    subject.tbs_certificate_bytes,
                    ec.ECDSA(subject.signature_hash_algorithm)
                )
            except Exception as e:
                raise RuntimeError(f"Verifying {subject.subject} issued "
                                   f"by {issuer.subject}: {e}")

            # 3. Gather CRL and check validity
            # (can be skipped for e.g. root of trust)
            if check_crl:
                crl_info = self.get_crl_info(subject)
                crl = crl_info["crl"]

                if not crl.is_signature_valid(issuer.public_key()):
                    raise RuntimeError("Invalid CRL signature from "
                                       f"{issuer.subject}")

                revoked = crl.get_revoked_certificate_by_serial_number(
                    subject.serial_number)
                if revoked is not None:
                    raise RuntimeError(f"{subject.subject} found in {issuer.subject} CRL")

                # If the CRL issuer chain is present, check that the first
                # element (the leaf) matches the given issuer
                issuer_chain = crl_info["issuer_chain"]
                if issuer_chain is not None:
                    leaf = issuer_chain[0]
                    if leaf != issuer:
                        raise RuntimeError(f"CRL issuer chain leaf {leaf.subject} does "
                                           f"not match certificate {subject.subject} "
                                           f"issuer {issuer.subject}")

                if crl_info["warning"] is not None:
                    warnings.append(crl_info["warning"])

            return {
                "valid": True,
                "warnings": warnings,
            }
        except Exception as e:
            return {
                "valid": False,
                "reason": str(e),
            }
