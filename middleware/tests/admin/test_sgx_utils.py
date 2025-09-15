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


from unittest import TestCase
from unittest.mock import patch, Mock
from parameterized import parameterized
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from hashlib import sha256
import ecdsa
from admin.sgx_utils import get_sgx_extensions, get_tcb_info, validate_tcb_info, \
                            get_intel_pcs_x509_crl
import logging

logging.disable(logging.CRITICAL)

TEST_CERTIFICATE = """
-----BEGIN CERTIFICATE-----
MIIE8jCCBJmgAwIBAgIVAJzdeT0t5GnBg8UERKXiUnECGiOPMAoGCCqGSM49BAMC
MHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoM
EUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UE
CAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTI1MDYyNDIyMDEyMFoXDTMyMDYyNDIyMDEy
MFowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZpY2F0ZTEaMBgGA1UE
CgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYD
VQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8
IZG02RowuzOQKmXZCmBjiMPUPW0+E1kVl1ufUkd3yBtA71B8bgt8DHaoUFZ1YAxu
ZZhPDvV13zZF9fzdyUxXo4IDDjCCAwowHwYDVR0jBBgwFoAUlW9dzb0b4elAScnU
9DPOAVcL3lQwawYDVR0fBGQwYjBgoF6gXIZaaHR0cHM6Ly9hcGkudHJ1c3RlZHNl
cnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92My9wY2tjcmw/Y2E9
cGxhdGZvcm0mZW5jb2Rpbmc9ZGVyMB0GA1UdDgQWBBT2LlxjZqMdkMyID5G57bLZ
kj0QPDAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADCCAjsGCSqGSIb4TQEN
AQSCAiwwggIoMB4GCiqGSIb4TQENAQEEELbSV7okFcKjOLO+IPh8XykwggFlBgoq
hkiG+E0BDQECMIIBVTAQBgsqhkiG+E0BDQECAQIBEDAQBgsqhkiG+E0BDQECAgIB
EDAQBgsqhkiG+E0BDQECAwIBAzAQBgsqhkiG+E0BDQECBAIBAzARBgsqhkiG+E0B
DQECBQICAP8wEQYLKoZIhvhNAQ0BAgYCAgD/MBAGCyqGSIb4TQENAQIHAgEBMBAG
CyqGSIb4TQENAQIIAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIK
AgEAMBAGCyqGSIb4TQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4
TQENAQINAgEAMBAGCyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAG
CyqGSIb4TQENAQIQAgEAMBAGCyqGSIb4TQENAQIRAgENMB8GCyqGSIb4TQENAQIS
BBAQEAMD//8BAAAAAAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqGSIb4TQEN
AQQEBgBgagAAADAPBgoqhkiG+E0BDQEFCgEBMB4GCiqGSIb4TQENAQYEEA1Xvw11
FROIHprYDubgabwwRAYKKoZIhvhNAQ0BBzA2MBAGCyqGSIb4TQENAQcBAQH/MBAG
CyqGSIb4TQENAQcCAQEAMBAGCyqGSIb4TQENAQcDAQEAMAoGCCqGSM49BAMCA0cA
MEQCICNTsVzcOYLck4STK/PAdCcTIqquVTmQRh40TSUBEaS4AiAzUN6Q3n/vEnSz
fQgkG+9VlNOMURjIGOl1qtg9jop4CQ==
-----END CERTIFICATE-----
"""

TEST_CERTIFICATE_ROOT = """
-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----
"""


class TestSgxUtils(TestCase):
    def test_get_sgx_extensions_ok(self):
        certificate = x509.load_pem_x509_certificate(TEST_CERTIFICATE.encode())
        extensions = get_sgx_extensions(certificate)
        self.assertEqual("b6d257ba2415c2a338b3be20f87c5f29", extensions["ppid"])
        tcb = extensions["tcb"]
        self.assertEqual(0x10, tcb["comp01"])
        self.assertEqual(0x10, tcb["comp02"])
        self.assertEqual(0x03, tcb["comp03"])
        self.assertEqual(0x03, tcb["comp04"])
        self.assertEqual(0xff, tcb["comp05"])
        self.assertEqual(0xff, tcb["comp06"])
        self.assertEqual(0x01, tcb["comp07"])
        self.assertEqual(0x00, tcb["comp08"])
        self.assertEqual(0x00, tcb["comp09"])
        self.assertEqual(0x00, tcb["comp10"])
        self.assertEqual(0x00, tcb["comp11"])
        self.assertEqual(0x00, tcb["comp12"])
        self.assertEqual(0x00, tcb["comp13"])
        self.assertEqual(0x00, tcb["comp14"])
        self.assertEqual(0x00, tcb["comp15"])
        self.assertEqual(0x00, tcb["comp16"])
        self.assertEqual(0x0d, tcb["pcesvn"])
        self.assertEqual("10100303ffff01000000000000000000", tcb["cpusvn"])
        self.assertEqual("0000", extensions["pceid"])
        self.assertEqual("00606a000000", extensions["fmspc"])

    def test_get_sgx_extensions_not_found(self):
        certificate = x509.load_pem_x509_certificate(TEST_CERTIFICATE_ROOT.encode())
        self.assertIsNone(get_sgx_extensions(certificate))


@patch("admin.sgx_utils.X509CertificateValidator")
@patch("admin.sgx_utils.x509")
@patch("admin.sgx_utils.split_pem_certificates")
@patch("admin.sgx_utils.requests")
class TestSgxUtilsGetTcbInfo(TestCase):
    def configure_mocks(self, requests, split_pem_certificates, mock_x509,
                        X509CertificateValidator, issuer_sig=None):
        mock_response = Mock()
        requests.get.return_value = mock_response
        mock_response.status_code = 200
        mock_response.headers = {
            "Content-Type": "application/json",
            "warning": "this is a warning",
            "TCB-Info-Issuer-Chain": "the issuer chain",
        }
        mock_response.text = """
            {
                "tcbInfo": {
                    "a": 1,
                    "b": 2,
                    "c": 3
                },
                "something": "else",
                "another": "thing",
                "signature": "<SIG>"
            }
            """
        self.mock_response = mock_response

        issuer_privkey = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        issuer_pubkey = issuer_privkey.verifying_key
        tcb_info_digest = sha256('{"a":1,"b":2,"c":3}'.encode()).digest()
        if issuer_sig is None:
            self.issuer_sig = issuer_privkey.sign_digest(
                tcb_info_digest, sigencode=ecdsa.util.sigencode_string)
        else:
            self.issuer_sig = issuer_sig
        mock_response.text = mock_response.text.replace("<SIG>", self.issuer_sig.hex())

        split_pem_certificates.return_value = ["cert-0", "cert-1"]
        self.cert0 = Mock()
        self.cert1 = Mock()

        self.cert0pk = Mock()
        self.cert0.public_key.return_value = self.cert0pk
        self.cert0pk.public_bytes.return_value = issuer_pubkey.to_string("compressed")

        def load_cert(pem):
            if pem == b"cert-0":
                return self.cert0
            elif pem == b"cert-1":
                return self.cert1
            else:
                raise Exception("Unknown cert")

        mock_x509.load_pem_x509_certificate.side_effect = load_cert

        self.validator = Mock()
        self.validator.validate.return_value = {
            "valid": True,
            "warnings": ["w1", "w2"],
        }
        X509CertificateValidator.return_value = self.validator

    @parameterized.expand([
        ("early"),
        ("standard"),
    ])
    def test_get_tcb_info_ok(self, requests, split_pem_certificates, mock_x509,
                             X509CertificateValidator, update):
        self.configure_mocks(requests, split_pem_certificates, mock_x509,
                             X509CertificateValidator)

        self.assertEqual({
            "tcb_info": {
                "tcbInfo": {
                    "a": 1,
                    "b": 2,
                    "c": 3,
                },
                "something": "else",
                "another": "thing",
                "signature": self.issuer_sig.hex(),
            },
            "warnings": [f"Getting the-url?fmspc=an-fmspc&update={update}: "
                         "this is a warning", "w1", "w2"],
        }, get_tcb_info("the-url", "an-fmspc", self.cert1, update=update))

        requests.get.assert_called_with(f"the-url?fmspc=an-fmspc&update={update}")
        X509CertificateValidator.assert_called_with(get_intel_pcs_x509_crl)
        self.validator.validate.assert_called_once()
        self.assertEqual(self.cert0, self.validator.validate.call_args_list[0].args[0])
        self.assertEqual(self.cert1, self.validator.validate.call_args_list[0].args[1])
        self.assertIsInstance(self.validator.validate.call_args_list[0].args[2], datetime)
        self.cert0pk.public_bytes.assert_called_once()
        self.cert0pk.public_bytes.assert_called_with(
            Encoding.X962, PublicFormat.CompressedPoint)

    def test_get_tcb_info_err_get(self, requests, split_pem_certificates, mock_x509,
                                  X509CertificateValidator):
        self.configure_mocks(requests, split_pem_certificates, mock_x509,
                             X509CertificateValidator)
        self.mock_response.status_code = 404

        with self.assertRaises(RuntimeError) as e:
            get_tcb_info("the-url", "an-fmspc", self.cert1, update="upd")
        self.assertIn("replied with status", str(e.exception))

        requests.get.assert_called_with("the-url?fmspc=an-fmspc&update=upd")
        X509CertificateValidator.assert_not_called()
        self.validator.validate.assert_not_called()
        self.cert0pk.public_bytes.assert_not_called()

    def test_get_tcb_info_err_ctype(self, requests, split_pem_certificates, mock_x509,
                                    X509CertificateValidator):
        self.configure_mocks(requests, split_pem_certificates, mock_x509,
                             X509CertificateValidator)
        self.mock_response.headers["Content-Type"] = "not/json"

        with self.assertRaises(RuntimeError) as e:
            get_tcb_info("the-url", "an-fmspc", self.cert1, update="upd")
        self.assertIn("content-type", str(e.exception))

        requests.get.assert_called_with("the-url?fmspc=an-fmspc&update=upd")
        X509CertificateValidator.assert_not_called()
        self.validator.validate.assert_not_called()
        self.cert0pk.public_bytes.assert_not_called()

    def test_get_tcb_info_err_nochain(self, requests, split_pem_certificates, mock_x509,
                                      X509CertificateValidator):
        self.configure_mocks(requests, split_pem_certificates, mock_x509,
                             X509CertificateValidator)
        self.mock_response.headers["TCB-Info-Issuer-Chain"] = None

        with self.assertRaises(RuntimeError) as e:
            get_tcb_info("the-url", "an-fmspc", self.cert1, update="upd")
        self.assertIn("certification chain", str(e.exception))

        requests.get.assert_called_with("the-url?fmspc=an-fmspc&update=upd")
        X509CertificateValidator.assert_not_called()
        self.validator.validate.assert_not_called()
        self.cert0pk.public_bytes.assert_not_called()

    def test_get_tcb_info_err_shortchain(self, requests, split_pem_certificates,
                                         mock_x509, X509CertificateValidator):
        self.configure_mocks(requests, split_pem_certificates, mock_x509,
                             X509CertificateValidator)
        split_pem_certificates.return_value = ["cert-0"]

        with self.assertRaises(RuntimeError) as e:
            get_tcb_info("the-url", "an-fmspc", self.cert1, update="upd")
        self.assertIn("at least two certificates", str(e.exception))

        requests.get.assert_called_with("the-url?fmspc=an-fmspc&update=upd")
        X509CertificateValidator.assert_not_called()
        self.validator.validate.assert_not_called()
        self.cert0pk.public_bytes.assert_not_called()

    def test_get_tcb_info_err_rot(self, requests, split_pem_certificates,
                                  mock_x509, X509CertificateValidator):
        self.configure_mocks(requests, split_pem_certificates, mock_x509,
                             X509CertificateValidator)

        other_root = Mock()
        other_root.subject = "other root"

        with self.assertRaises(RuntimeError) as e:
            get_tcb_info("the-url", "an-fmspc", other_root, update="upd")
        self.assertIn("does not match", str(e.exception))
        self.assertIn("other root", str(e.exception))

        requests.get.assert_called_with("the-url?fmspc=an-fmspc&update=upd")
        X509CertificateValidator.assert_not_called()
        self.validator.validate.assert_not_called()
        self.cert0pk.public_bytes.assert_not_called()

    def test_get_tcb_info_err_chain_iv(self, requests, split_pem_certificates,
                                       mock_x509, X509CertificateValidator):
        self.configure_mocks(requests, split_pem_certificates, mock_x509,
                             X509CertificateValidator)

        self.validator.validate.return_value = {
            "valid": False,
            "reason": "oops"
        }

        with self.assertRaises(RuntimeError) as e:
            get_tcb_info("the-url", "an-fmspc", self.cert1, update="upd")
        self.assertIn("issuer chain", str(e.exception))
        self.assertIn("oops", str(e.exception))

        requests.get.assert_called_with("the-url?fmspc=an-fmspc&update=upd")
        X509CertificateValidator.assert_called_with(get_intel_pcs_x509_crl)
        self.validator.validate.assert_called_once()
        self.assertEqual(self.cert0, self.validator.validate.call_args_list[0].args[0])
        self.assertEqual(self.cert1, self.validator.validate.call_args_list[0].args[1])
        self.assertIsInstance(self.validator.validate.call_args_list[0].args[2], datetime)
        self.cert0pk.public_bytes.assert_not_called()

    def test_get_tcb_info_err_tcb_sig(self, requests, split_pem_certificates,
                                      mock_x509, X509CertificateValidator):
        isig = bytes.fromhex("aa"*32+"bb"*32)
        self.configure_mocks(requests, split_pem_certificates, mock_x509,
                             X509CertificateValidator, issuer_sig=isig)

        with self.assertRaises(RuntimeError) as e:
            get_tcb_info("the-url", "an-fmspc", self.cert1, update="upd")
        self.assertIn("Signature verification failed", str(e.exception))

        requests.get.assert_called_with("the-url?fmspc=an-fmspc&update=upd")
        X509CertificateValidator.assert_called_with(get_intel_pcs_x509_crl)
        self.validator.validate.assert_called_once()
        self.assertEqual(self.cert0, self.validator.validate.call_args_list[0].args[0])
        self.assertEqual(self.cert1, self.validator.validate.call_args_list[0].args[1])
        self.assertIsInstance(self.validator.validate.call_args_list[0].args[2], datetime)
        self.cert0pk.public_bytes.assert_called_once()
        self.cert0pk.public_bytes.assert_called_with(
            Encoding.X962, PublicFormat.CompressedPoint)


class TestSgxUtilsValidateTcbInfo(TestCase):
    def setUp(self):
        self.pck_info = {
            "ppid": "aa"*32,
            "tcb": {
                "comp01": 11,
                "comp02": 22,
                "comp03": 33,
                "comp04": 44,
                "comp05": 55,
                "comp06": 66,
                "comp07": 77,
                "comp08": 88,
                "comp09": 99,
                "comp10": 1010,
                "comp11": 1111,
                "comp12": 1212,
                "comp13": 1313,
                "comp14": 1414,
                "comp15": 1515,
                "comp16": 1616,
                "pcesvn": 1717,
                "cpusvn": "bb"*32,
            },
            "pceid": "abcd",
            "fmspc": "cc"*6
        }

        self.tcb_info = {
            "tcbInfo": {
                "id": "SGX",
                "version": 3,
                "issueDate": "2025-09-05T03:41:29Z",
                "nextUpdate": "2025-10-05T03:41:29Z",
                "fmspc": "00606a000000",
                "pceId": "0000",
                "tcbType": 0,
                "tcbEvaluationDataNumber": 1234,
                "tcbLevels": [
                    {
                        "tcb": {
                            "sgxtcbcomponents": [
                                {
                                    "svn": 10,
                                },
                                {
                                    "svn": 20,
                                },
                                {
                                    "svn": 30,
                                },
                                {
                                    "svn": 3,
                                },
                                {
                                    "svn": 255
                                },
                                {
                                    "svn": 255
                                },
                                {
                                    "svn": 1
                                },
                                {
                                    "svn": 0
                                },
                                {
                                    "svn": 0
                                },
                                {
                                    "svn": 0
                                },
                                {
                                    "svn": 0
                                },
                                {
                                    "svn": 0
                                },
                                {
                                    "svn": 0
                                },
                                {
                                    "svn": 0
                                },
                                {
                                    "svn": 0
                                },
                                {
                                    "svn": 0
                                }
                            ],
                            "pcesvn": 13
                        },
                        "tcbDate": "doesntmatter",
                        "tcbStatus": "neither",
                        "advisoryIDs": [
                            "we-dont-care",
                            "or-about-this-one"
                        ]
                    },
                    {
                        "tcb": {
                            "sgxtcbcomponents": [
                                {
                                    "svn": 10
                                },
                                {
                                    "svn": 21
                                },
                                {
                                    "svn": 32
                                },
                                {
                                    "svn": 43
                                },
                                {
                                    "svn": 54
                                },
                                {
                                    "svn": 65
                                },
                                {
                                    "svn": 76
                                },
                                {
                                    "svn": 87
                                },
                                {
                                    "svn": 98
                                },
                                {
                                    "svn": 1009
                                },
                                {
                                    "svn": 1110
                                },
                                {
                                    "svn": 1211
                                },
                                {
                                    "svn": 1312
                                },
                                {
                                    "svn": 1413
                                },
                                {
                                    "svn": 1514
                                },
                                {
                                    "svn": 1615
                                }
                            ],
                            "pcesvn": 1716
                        },
                        "tcbDate": "the-date-we-want",
                        "tcbStatus": "the-status-we-want",
                        "advisoryIDs": [
                            "the-advisory-1",
                            "the-advisory-2",
                            "the-advisory-3"
                        ]
                    }
                ]
            },
            "signature": "not-used-here"
        }

    def test_validate_tcb_info_ok(self):
        self.assertEqual({
            "valid": True,
            "status": "the-status-we-want",
            "date": "the-date-we-want",
            "advisories": ["the-advisory-1", "the-advisory-2", "the-advisory-3"],
            "svns": [
                "Comp 01: 11 >= 10",
                "Comp 02: 22 >= 21",
                "Comp 03: 33 >= 32",
                "Comp 04: 44 >= 43",
                "Comp 05: 55 >= 54",
                "Comp 06: 66 >= 65",
                "Comp 07: 77 >= 76",
                "Comp 08: 88 >= 87",
                "Comp 09: 99 >= 98",
                "Comp 10: 1010 >= 1009",
                "Comp 11: 1111 >= 1110",
                "Comp 12: 1212 >= 1211",
                "Comp 13: 1313 >= 1312",
                "Comp 14: 1414 >= 1413",
                "Comp 15: 1515 >= 1514",
                "Comp 16: 1616 >= 1615",
                "PCESVN: 1717 >= 1716",
            ],
            "edn": 1234,
        }, validate_tcb_info(self.pck_info, self.tcb_info["tcbInfo"]))

    def test_validate_tcb_info_notfound(self):
        self.tcb_info["tcbInfo"]["tcbLevels"] = self.tcb_info["tcbInfo"]["tcbLevels"][0:1]
        self.assertEqual({
            "valid": False,
            "reason": "TCB level is unsupported",
        }, validate_tcb_info(self.pck_info, self.tcb_info["tcbInfo"]))

    def test_validate_tcb_info_malformed(self):
        self.tcb_info = {
            "tcbInfo": {
                "something": "else"
            }
        }

        res = validate_tcb_info(self.pck_info, self.tcb_info["tcbInfo"])
        self.assertFalse(res["valid"])
        self.assertIn("While validating TCB information", res["reason"])
