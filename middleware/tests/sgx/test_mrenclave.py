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
from unittest.mock import patch, Mock, mock_open
from admin.misc import AdminError
from mrenclave import EnclaveBinary

import logging

logging.disable(logging.CRITICAL)


class TestEnclaveBinary(TestCase):
    @patch("builtins.open", new_callable=mock_open, read_data=b"some-binary-data")
    @patch("mrenclave.ELFFile")
    @patch("mrenclave.EnclaveProperties")
    def test_load_binary(self, mock_properties, mock_elf, mock_enclave_file):
        mock_elf_instance = Mock()
        mock_oeinfo = Mock()
        mock_properties_instance = Mock()
        mock_oeinfo.data.return_value = b"oeinfo-data"
        mock_elf_instance.get_section_by_name.return_value = mock_oeinfo
        mock_elf.return_value = mock_elf_instance
        mock_properties.return_value = mock_properties_instance

        enclave_bin = EnclaveBinary("existent-file-path")
        enclave_bin.load_binary()

        self.assertIsNotNone(enclave_bin.enclave_properties)
        mock_enclave_file.assert_called_with("existent-file-path", "rb")
        mock_elf_instance.get_section_by_name.assert_called_with(".oeinfo")
        mock_properties.assert_called_with(b"oeinfo-data")

    def test_get_mrenclave(self):
        mock_properties_instance = Mock()
        mock_properties_instance.get_mrenclave.return_value = "mrenclave-value"

        enclave_bin = EnclaveBinary("existent-file-path")
        enclave_bin.enclave_properties = mock_properties_instance

        self.assertEqual(enclave_bin.get_mrenclave(), "mrenclave-value")

    def test_file_not_found(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            enclave_bin = EnclaveBinary("non-existent-file-path")
            with self.assertRaises(AdminError):
                enclave_bin.load_binary()

    @patch("builtins.open", new_callable=mock_open, read_data=b"some-binary-data")
    @patch("mrenclave.ELFFile")
    def test_oeinfo_not_found(self, mock_elf, mock_enclave_file):
        mock_elf_instance = Mock()
        mock_elf_instance.get_section_by_name.return_value = None
        mock_elf.return_value = mock_elf_instance

        enclave_bin = EnclaveBinary("existent-file-path")
        with self.assertRaises(AdminError):
            enclave_bin.load_binary()

        mock_enclave_file.assert_called_with("existent-file-path", "rb")
        mock_elf_instance.get_section_by_name.assert_called_with(".oeinfo")
