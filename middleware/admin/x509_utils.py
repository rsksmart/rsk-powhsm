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
import requests
from cryptography import x509
from urllib.parse import unquote as url_unquote


def split_pem_certificates(pem_data):
    pattern = r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
    certs = re.findall(pattern, pem_data, flags=re.DOTALL)
    return certs


def get_intel_pcs_x509_crl(url):
    ra_res = requests.get(url)
    if ra_res.status_code != 200:
        raise RuntimeError(f"Error fetching CRL from {url}")

    try:
        # Parse CRL
        ctype = ra_res.headers["Content-Type"]
        if ctype in ["application/x-pem-file"]:
            crl = x509.load_pem_x509_crl(ra_res.content)
        elif ctype in ["application/pkix-crl", "application/x-x509-ca-cert"]:
            crl = x509.load_der_x509_crl(ra_res.content)
        else:
            raise RuntimeError(f"Unknown CRL encoding: {ctype}")

        # Parse certification chain (if any)
        issuer_chain = ra_res.headers.get("SGX-PCK-CRL-Issuer-Chain")
        if issuer_chain is not None:
            issuer_chain = split_pem_certificates(url_unquote(issuer_chain))
            issuer_chain = list(map(
                lambda pem: x509.load_pem_x509_certificate(pem.encode()), issuer_chain))

        warning = ra_res.headers.get("warning")
        if warning is not None:
            warning = f"Getting {url}: {warning}"

        response = {
            "crl": crl,
            "issuer_chain": issuer_chain,
            "warning": warning,
        }

        return response
    except Exception as e:
        raise RuntimeError(f"While fetching CRL from {url}: {e}")
