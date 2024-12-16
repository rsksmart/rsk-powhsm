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

from comm.cstruct import CStruct


class SgxEnvelope(CStruct):
    """
    sgx_envelope_t

    sgx_quote_t quote
    sgx_quote_tail_t quote_tail
    sgx_quote_auth_data_t quote_auth_data
    """

    def __init__(self, envelope_bytes, custom_message_bytes, offset=0, little=True):
        super().__init__(envelope_bytes, offset, little)
        offset += self.get_bytelength()

        qead = SgxQeAuthData(envelope_bytes, offset, little)
        offset += qead.get_total_bytelength()
        self.qe_auth_data = qead

        qecd = SgxQeCertData(envelope_bytes, offset, little)
        offset += qecd.get_total_bytelength()
        self.qe_cert_data = qecd

        if envelope_bytes[offset:] != custom_message_bytes:
            raise ValueError("Unexpected custom message in envelope tail")
        self.custom_message = custom_message_bytes

##############################################################################
# Types below taken from OpenEnclave's include/openenclave/bits/sgx/sgxtypes.h
##############################################################################


class SgxAttributes(CStruct):
    """
    sgx_attributes_t

    uint64_t   flags
    uint64_t   xfrm
    """


class SgxReportData(CStruct):
    """
    sgx_report_data_t

    uint8_t field 64
    """


class SgxReportBody(CStruct):
    """
    sgx_report_body_t

    uint8_t cpusvn 16
    uint32_t miscselect
    uint8_t reserved1 12
    uint8_t isvextprodid 16
    sgx_attributes_t attributes
    uint8_t mrenclave 32
    uint8_t reserved2 32
    uint8_t mrsigner 32
    uint8_t reserved3 32
    uint8_t configid 64
    uint16_t isvprodid
    uint16_t isvsvn
    uint16_t configsvn
    uint8_t reserved4 42
    uint8_t isvfamilyid 16
    sgx_report_data_t report_data
    """


class SgxEcdsa256Signature(CStruct):
    """
    sgx_ecdsa256_signature_t

    uint8_t r 32
    uint8_t s 32
    """


class SgxEcdsa256Key(CStruct):
    """
    sgx_ecdsa256_key_t

    uint8_t x 32
    uint8_t y 32
    """


class SgxQuote(CStruct):
    """
    sgx_quote_t

    uint16_t version
    uint16_t sign_type
    uint32_t tee_type
    uint16_t qe_svn
    uint16_t pce_svn
    uint8_t uuid 16
    uint8_t user_data 20
    sgx_report_body_t report_body
    """


# This is actually part of sgx_quote_t, separated
# for pratical reasons since the signature doesn't include
# this field
class SgxQuoteTail(CStruct):
    """
    sgx_quote_tail_t

    uint32_t signature_len
    """


class SgxQuoteAuthData(CStruct):
    """
    sgx_quote_auth_data_t

    sgx_ecdsa256_signature_t signature
    sgx_ecdsa256_key_t attestation_key
    sgx_report_body_t qe_report_body
    sgx_ecdsa256_signature_t qe_report_body_signature
    """

####################################################################
# The following two structs are augmented with content parsing logic
####################################################################


class SgxQeAuthData(CStruct):
    """
    sgx_qe_auth_data_t

    uint16_t size
    """

    def __init__(self, value, offset=0, little=True):
        super().__init__(value, offset, little)
        os = offset + self.get_bytelength()
        data = value[os:os+self.size]
        if len(data) != self.size:
            raise ValueError(f"Expected {self.size} data bytes but only got {len(data)}")
        self.data = data

    def get_total_bytelength(self):
        return self.get_bytelength() + len(self.data)


class SgxQeCertData(SgxQeAuthData):
    """
    sgx_qe_cert_data_t

    uint16_t type
    uint32_t size
    """
    SPEC = None
    TYPENAME = None

    X509_START_MARKER = b"-----BEGIN CERTIFICATE-----\n"
    X509_END_MARKER = b"\n-----END CERTIFICATE-----\n"

    def __init__(self, value, offset=0, little=True):
        super().__init__(value, offset, little)
        self.certs = list(map(lambda c: c.replace(self.X509_START_MARKER, b""),
                              filter(lambda c:
                                     c.strip().startswith(self.X509_START_MARKER),
                                     self.data.split(self.X509_END_MARKER))))
