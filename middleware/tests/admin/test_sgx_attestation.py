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

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch
from parameterized import parameterized
from admin.sgx_attestation import do_attestation
from admin.misc import AdminError


@patch("sys.stdout")
@patch("admin.sgx_attestation.HSMCertificateV2Element")
@patch("admin.sgx_attestation.HSMCertificateV2")
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
                   HSMCertificateV2, HSMCertificateV2Element):
        self.get_hsm = get_hsm
        self.get_ud_value_for_attestation = get_ud_value_for_attestation
        self.do_unlock = do_unlock
        self.HSMCertificateV2 = HSMCertificateV2
        self.HSMCertificateV2Element = HSMCertificateV2Element

        self.hsm = Mock()
        self.hsm.get_powhsm_attestation.return_value = "the-attestation"
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
        self.HSMCertificateV2Element.assert_called_with("the-attestation")
        elem = self.HSMCertificateV2Element.return_value
        cert = self.HSMCertificateV2.return_value
        cert.add_element.assert_called_with(elem)
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
        self.HSMCertificateV2.assert_not_called()
        self.HSMCertificateV2Element.assert_not_called()

    def test_adm_err(self, *args):
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
        self.HSMCertificateV2.assert_not_called()
        self.HSMCertificateV2Element.assert_not_called()
