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
from unittest.mock import mock_open, call, patch
from signonetime import main
import ecdsa
import logging

logging.disable(logging.CRITICAL)


class TestSignOneTime(TestCase):
    @patch("signonetime.compute_app_hash")
    def test_ok_two_apps(self, compute_app_hash_mock):
        compute_app_hash_mock.side_effect = lambda path: (path[0]*32).encode()

        with patch("sys.stdout"):
            with patch("sys.argv", ["_",
                                    "-a app/path/one.hex,/bin/path/to/two.hex",
                                    "-p /some/where/public.txt"]):
                with patch("builtins.open", mock_open()) as open_mock:
                    with self.assertRaises(SystemExit) as e:
                        main()
                    self.assertEqual(e.exception.code, 0)

        self.assertEqual([call("/some/where/public.txt", "wb"),
                          call("app/path/one.hex.sig", "wb"),
                          call("/bin/path/to/two.hex.sig", "wb")],
                         open_mock.call_args_list)
        write_calls = open_mock.return_value.write.call_args_list
        self.assertEqual(3, len(write_calls))
        public_key = ecdsa.VerifyingKey.from_string(
            bytes.fromhex(write_calls[0][0][0].decode()),
            curve=ecdsa.SECP256k1)
        sig_one = bytes.fromhex(write_calls[1][0][0].decode())
        sig_two = bytes.fromhex(write_calls[2][0][0].decode())

        public_key.verify_digest(
            sig_one,
            b"a"*32,
            sigdecode=ecdsa.util.sigdecode_der)  # This throws if signature is invalid

        public_key.verify_digest(
            sig_two,
            b"/"*32,
            sigdecode=ecdsa.util.sigdecode_der)  # This throws if signature is invalid
