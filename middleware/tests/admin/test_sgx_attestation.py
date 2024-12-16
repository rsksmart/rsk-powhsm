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

import ecdsa
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch, call
from parameterized import parameterized
from admin.sgx_attestation import do_attestation
from admin.misc import AdminError


@patch("sys.stdout")
@patch("admin.sgx_attestation.HSMCertificateV2ElementX509")
@patch("admin.sgx_attestation.HSMCertificateV2ElementSGXAttestationKey")
@patch("admin.sgx_attestation.HSMCertificateV2ElementSGXQuote")
@patch("admin.sgx_attestation.HSMCertificateV2")
@patch("admin.sgx_attestation.SgxEnvelope")
@patch("admin.sgx_attestation.do_unlock")
@patch("admin.sgx_attestation.get_ud_value_for_attestation")
@patch("admin.sgx_attestation.get_hsm")
class TestSgxAttestation(TestCase):
    def setUp(self):
        options = SimpleNamespace()
        options.output_file_path = "an-output-file"
        options.no_unlock = False
        options.verbose = "is-verbose"
        options.attestation_ud_source = "an-ud-source"
        self.options = options

    def setupMocks(self, get_hsm, get_ud_value_for_attestation, do_unlock,
                   SgxEnvelope, HSMCertificateV2, HSMCertificateV2ElementSGXQuote,
                   HSMCertificateV2ElementSGXAttestationKey, HSMCertificateV2ElementX509):
        self.get_hsm = get_hsm
        self.get_ud_value_for_attestation = get_ud_value_for_attestation
        self.do_unlock = do_unlock
        self.SgxEnvelope = SgxEnvelope
        self.HSMCertificateV2 = HSMCertificateV2
        self.HSMCertificateV2ElementSGXQuote = HSMCertificateV2ElementSGXQuote
        self.HSMCertificateV2ElementSGXAttestationKey = \
            HSMCertificateV2ElementSGXAttestationKey
        self.HSMCertificateV2ElementX509 = HSMCertificateV2ElementX509

        self.hsm = Mock()
        self.hsm.get_powhsm_attestation.return_value = {
            "envelope": "11"*32,
            "message": "22"*32,
        }
        quote = SimpleNamespace(**{"get_raw_data": lambda: "quote-raw-data"})
        sig = SimpleNamespace(**{"r": b"a"*32, "s": b"a"*32})
        self.att_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p).\
            get_verifying_key()
        att_key_str = self.att_key.to_string()
        attkey = SimpleNamespace(**{"x": att_key_str[:32], "y": att_key_str[32:]})
        qesig = SimpleNamespace(**{"r": b"c"*32, "s": b"c"*32})
        qad = SimpleNamespace(**{
            "signature": sig,
            "attestation_key": attkey,
            "qe_report_body": SimpleNamespace(**{
                "get_raw_data": lambda: "qerb-raw-data"}),
            "qe_report_body_signature": qesig,
        })
        qead = SimpleNamespace(**{
            "data": "qead-data",
        })
        qecd = SimpleNamespace(**{
            "certs": ["qecd-cert-0", "qecd-cert-1"],
        })
        envelope = SimpleNamespace(**{
            "quote": quote,
            "quote_auth_data": qad,
            "qe_auth_data": qead,
            "qe_cert_data": qecd,
            "custom_message": "a-custom-message",
        })
        self.SgxEnvelope.return_value = envelope

        self.HSMCertificateV2ElementSGXQuote.return_value = "quote_elem"
        self.HSMCertificateV2ElementSGXAttestationKey.return_value = "attkey_elem"
        self.HSMCertificateV2ElementX509.side_effect = ["cert0_elem", "cert1_elem"]

        get_hsm.return_value = self.hsm
        get_ud_value_for_attestation.return_value = "some-random-value"

    @parameterized.expand([
        ("unlock", False),
        ("no_unlock", True),
    ])
    def test_ok(self, *args):
        self.setupMocks(*args[:-3])
        self.options.no_unlock = args[-1]

        do_attestation(self.options)

        self.get_ud_value_for_attestation.assert_called_with("an-ud-source")
        if self.options.no_unlock:
            self.do_unlock.assert_not_called()
        else:
            self.do_unlock.assert_called_with(self.options, label=False)
        self.get_hsm.assert_called_with("is-verbose")
        self.hsm.get_powhsm_attestation.assert_called_with("some-random-value")
        self.hsm.disconnect.assert_called()
        self.SgxEnvelope.assert_called_with(
            bytes.fromhex("11"*32),
            bytes.fromhex("22"*32),
        )
        self.HSMCertificateV2ElementSGXQuote.assert_called_with(
            name="quote",
            message="quote-raw-data",
            custom_data="a-custom-message",
            signature=bytes.fromhex("30440220"+"61"*32+"0220"+"61"*32),
            signed_by="attestation",
        )
        self.HSMCertificateV2ElementSGXAttestationKey.assert_called_with(
            name="attestation",
            message="qerb-raw-data",
            key=self.att_key.to_string("uncompressed"),
            auth_data="qead-data",
            signature=bytes.fromhex("30440220"+"63"*32+"0220"+"63"*32),
            signed_by="quoting_enclave",
        )
        self.HSMCertificateV2ElementX509.assert_has_calls([
            call(
                name="quoting_enclave",
                message="qecd-cert-0",
                signed_by="platform_ca",
            ),
            call(
                name="platform_ca",
                message="qecd-cert-1",
                signed_by="sgx_root",
            )
        ])
        cert = self.HSMCertificateV2.return_value
        cert.add_element.assert_has_calls([
            call("quote_elem"),
            call("attkey_elem"),
            call("cert0_elem"),
            call("cert1_elem")
        ])
        cert.save_to_jsonfile.assert_called_with("an-output-file")

    def test_no_output_path(self, *args):
        self.setupMocks(*args[:-1])
        self.options.output_file_path = None

        with self.assertRaises(AdminError) as e:
            do_attestation(self.options)
        self.assertIn("output file", str(e.exception))

        self.get_ud_value_for_attestation.assert_not_called()
        self.get_hsm.assert_not_called()
        self.hsm.get_powhsm_attestation.assert_not_called()
        self.do_unlock.assert_not_called()
        self.SgxEnvelope.assert_not_called()
        self.HSMCertificateV2.assert_not_called()
        self.HSMCertificateV2ElementSGXQuote.assert_not_called()
        self.HSMCertificateV2ElementSGXAttestationKey.assert_not_called()
        self.HSMCertificateV2ElementX509.assert_not_called()

    def test_adm_err_get_attestation(self, *args):
        self.setupMocks(*args[:-1])

        self.hsm.get_powhsm_attestation.side_effect = RuntimeError("an error")

        with self.assertRaises(RuntimeError) as e:
            do_attestation(self.options)
        self.assertIn("an error", str(e.exception))

        self.get_ud_value_for_attestation.assert_called_with("an-ud-source")
        self.do_unlock.assert_called_with(self.options, label=False)
        self.get_hsm.assert_called_with("is-verbose")
        self.hsm.get_powhsm_attestation.assert_called_with("some-random-value")
        self.hsm.disconnect.assert_not_called()
        self.SgxEnvelope.assert_not_called()
        self.HSMCertificateV2.assert_not_called()
        self.HSMCertificateV2ElementSGXQuote.assert_not_called()
        self.HSMCertificateV2ElementSGXAttestationKey.assert_not_called()
        self.HSMCertificateV2ElementX509.assert_not_called()

    def test_adm_err_envelope_parsing(self, *args):
        self.setupMocks(*args[:-1])

        self.SgxEnvelope.side_effect = ValueError("an error")

        with self.assertRaises(AdminError) as e:
            do_attestation(self.options)
        self.assertIn("envelope parse error", str(e.exception))

        self.get_ud_value_for_attestation.assert_called_with("an-ud-source")
        self.do_unlock.assert_called_with(self.options, label=False)
        self.get_hsm.assert_called_with("is-verbose")
        self.hsm.get_powhsm_attestation.assert_called_with("some-random-value")
        self.hsm.disconnect.assert_called()
        self.SgxEnvelope.assert_called_with(
            bytes.fromhex("11"*32),
            bytes.fromhex("22"*32),
        )
        self.HSMCertificateV2.assert_not_called()
        self.HSMCertificateV2ElementSGXQuote.assert_not_called()
        self.HSMCertificateV2ElementSGXAttestationKey.assert_not_called()
        self.HSMCertificateV2ElementX509.assert_not_called()
