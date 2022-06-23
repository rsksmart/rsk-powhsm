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
from unittest.mock import patch, call
from admin.authorize_signer import do_authorize_signer
from admin.misc import AdminError

import logging

logging.disable(logging.CRITICAL)


@patch("admin.authorize_signer.SignerAuthorization")
@patch("admin.authorize_signer.do_unlock")
@patch("admin.authorize_signer.get_hsm")
@patch("admin.authorize_signer.dispose_hsm")
class TestAuthorizeSigner(TestCase):
    def test_ok(self, dispose_hsm_mock, get_hsm_mock, do_unlock_mock, sa_mock):
        with patch("sys.stdout"):
            options = SimpleNamespace(
                signer_authorization_file_path="/a/file/path",
                another="option",
                andfinally="anotherone",
                verbose="is-verbose",
            )
            do_authorize_signer(options)

        self.assertEqual([call("/a/file/path")],
                         sa_mock.from_jsonfile.call_args_list)
        self.assertEqual([call(options, label=False, exit=False)],
                         do_unlock_mock.call_args_list)
        self.assertEqual([call("is-verbose")], get_hsm_mock.call_args_list)
        self.assertEqual([call(sa_mock.from_jsonfile.return_value)],
                         get_hsm_mock.return_value.authorize_signer.call_args_list)
        self.assertEqual([call(get_hsm_mock.return_value)],
                         dispose_hsm_mock.call_args_list)

    def test_jsonfile_error(self, dispose_hsm_mock, get_hsm_mock, do_unlock_mock,
                            sa_mock):
        sa_mock.from_jsonfile.side_effect = Exception("loading-jsonfile")

        with patch("sys.stdout"):
            options = SimpleNamespace(
                signer_authorization_file_path="/a/file/path",
                another="option",
                andfinally="anotherone",
                verbose="is-verbose",
            )
            with self.assertRaises(AdminError):
                do_authorize_signer(options)

        self.assertEqual([call("/a/file/path")],
                         sa_mock.from_jsonfile.call_args_list)
        self.assertEqual([], do_unlock_mock.call_args_list)
        self.assertEqual([], get_hsm_mock.call_args_list)
        self.assertEqual([], dispose_hsm_mock.call_args_list)

    def test_unlock_error(self, dispose_hsm_mock, get_hsm_mock, do_unlock_mock, sa_mock):
        do_unlock_mock.side_effect = Exception("unlocking")

        with patch("sys.stdout"):
            options = SimpleNamespace(
                signer_authorization_file_path="/a/file/path",
                another="option",
                andfinally="anotherone",
                verbose="is-verbose",
            )
            with self.assertRaises(AdminError):
                do_authorize_signer(options)

        self.assertEqual([call("/a/file/path")],
                         sa_mock.from_jsonfile.call_args_list)
        self.assertEqual([call(options, label=False, exit=False)],
                         do_unlock_mock.call_args_list)
        self.assertEqual([], get_hsm_mock.call_args_list)
        self.assertEqual([], dispose_hsm_mock.call_args_list)

    def test_get_hsm_error(self, dispose_hsm_mock, get_hsm_mock, do_unlock_mock, sa_mock):
        get_hsm_mock.side_effect = Exception("connecting-to-hsm")

        with patch("sys.stdout"):
            options = SimpleNamespace(
                signer_authorization_file_path="/a/file/path",
                another="option",
                andfinally="anotherone",
                verbose="is-verbose",
            )
            with self.assertRaises(AdminError):
                do_authorize_signer(options)

        self.assertEqual([call("/a/file/path")],
                         sa_mock.from_jsonfile.call_args_list)
        self.assertEqual([call(options, label=False, exit=False)],
                         do_unlock_mock.call_args_list)
        self.assertEqual([call("is-verbose")], get_hsm_mock.call_args_list)
        self.assertEqual([call(None)], dispose_hsm_mock.call_args_list)

    def test_auth_error(self, dispose_hsm_mock, get_hsm_mock, do_unlock_mock, sa_mock):
        get_hsm_mock.return_value.authorize_signer.side_effect = \
            Exception("authorising-signer")

        with patch("sys.stdout"):
            options = SimpleNamespace(
                signer_authorization_file_path="/a/file/path",
                another="option",
                andfinally="anotherone",
                verbose="is-verbose",
            )
            with self.assertRaises(AdminError):
                do_authorize_signer(options)

        self.assertEqual([call("/a/file/path")],
                         sa_mock.from_jsonfile.call_args_list)
        self.assertEqual([call(options, label=False, exit=False)],
                         do_unlock_mock.call_args_list)
        self.assertEqual([call("is-verbose")], get_hsm_mock.call_args_list)
        self.assertEqual([call(get_hsm_mock.return_value)],
                         dispose_hsm_mock.call_args_list)
