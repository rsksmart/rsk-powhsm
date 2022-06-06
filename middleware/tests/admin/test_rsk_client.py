# The MIT License (MIT)
#
# Copyright (c) 2022 RSK Labs Ltd
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
from unittest.mock import call, patch
from admin.rsk_client import RskClient, RskClientError

import json
import os


@patch("requests.post")
@patch("os.urandom")
class TestRskClient(TestCase):
    def setUp(self):
        self.url = 'an-url'
        self.random_number = os.urandom(2)
        self.request_id = int.from_bytes(
            self.random_number,
            byteorder="big",
            signed=False
        )
        self.post_result = 'aa' * 65
        post_response = {
            'status_code': 200,
            'text': json.dumps({
                'id': self.request_id,
                'result': self.post_result
            })
        }
        self.post_response = SimpleNamespace(**post_response)

    def test_get_best_block_number(self, random_mock, post_mock):
        random_mock.return_value = self.random_number
        post_mock.return_value = self.post_response

        client = RskClient(self.url)
        best_block = client.get_best_block_number()

        self.assertEqual([call(self.url,
                               data=json.dumps({
                                   "jsonrpc": "2.0",
                                   "id": self.request_id,
                                   "method": "eth_blockNumber",
                                   "params": [],
                               }),
                               headers={"content-type": "application/json"})],
                         post_mock.call_args_list)
        self.assertEqual(int(self.post_result, 16), best_block)

    def test_get_best_block_number_server_error(self, random_mock, post_mock):
        random_mock.return_value = self.random_number
        post_response = self.post_response
        post_response.status_code = 400
        post_mock.return_value = post_response

        client = RskClient(self.url)
        with self.assertRaises(RskClientError) as e:
            client.get_best_block_number()

        self.assertEqual([call(self.url,
                               data=json.dumps({
                                   "jsonrpc": "2.0",
                                   "id": self.request_id,
                                   "method": "eth_blockNumber",
                                   "params": [],
                               }),
                               headers={"content-type": "application/json"})],
                         post_mock.call_args_list)
        self.assertEqual("While getting the best block number: While calling the "
                         "'eth_blockNumber' method: Got 400 response from the server",
                         str(e.exception))

    def test_get_best_block_number_id_error(self, random_mock, post_mock):
        random_mock.return_value = self.random_number
        post_response = self.post_response
        wrong_id = self.request_id + 1
        post_response.text = json.dumps({
            'id': wrong_id,
            'result': self.post_result
        })
        post_mock.return_value = post_response

        client = RskClient(self.url)
        with self.assertRaises(RskClientError) as e:
            client.get_best_block_number()

        self.assertEqual([call(self.url,
                               data=json.dumps({
                                   "jsonrpc": "2.0",
                                   "id": self.request_id,
                                   "method": "eth_blockNumber",
                                   "params": [],
                               }),
                               headers={"content-type": "application/json"})],
                         post_mock.call_args_list)
        self.assertEqual("While getting the best block number: While calling the "
                         f"'eth_blockNumber' method: Unexpected response id {wrong_id} "
                         f"(expecting {self.request_id})",
                         str(e.exception))

    def test_get_block_by_number(self, random_mock, post_mock):
        random_mock.return_value = self.random_number
        post_mock.return_value = self.post_response
        block_number = 123456789

        client = RskClient(self.url)
        best_block = client.get_block_by_number(block_number)
        expected_call = [call(self.url,
                              data=json.dumps({
                                  "jsonrpc": "2.0",
                                  "id": self.request_id,
                                  "method": "eth_getBlockByNumber",
                                  "params": [hex(block_number), False],
                              }),
                              headers={"content-type": "application/json"})]

        self.assertEqual(expected_call, post_mock.call_args_list)
        self.assertEqual(self.post_result, best_block)

    def test_get_block_by_number_server_error(self, random_mock, post_mock):
        random_mock.return_value = self.random_number
        post_response = self.post_response
        post_response.status_code = 400
        post_mock.return_value = post_response
        block_number = 123456789

        client = RskClient(self.url)
        with self.assertRaises(RskClientError) as e:
            client.get_block_by_number(block_number)

        expected_call = [call(self.url,
                              data=json.dumps({
                                  "jsonrpc": "2.0",
                                  "id": self.request_id,
                                  "method": "eth_getBlockByNumber",
                                  "params": [hex(block_number), False],
                              }),
                              headers={"content-type": "application/json"})]

        self.assertEqual(expected_call, post_mock.call_args_list)
        self.assertEqual("While getting the block by number: While calling the "
                         "'eth_getBlockByNumber' method: Got 400 response "
                         "from the server",
                         str(e.exception))

    def test_get_block_by_number_id_error(self, random_mock, post_mock):
        random_mock.return_value = self.random_number
        post_response = self.post_response
        wrong_id = self.request_id + 1
        post_response.text = json.dumps({
            'id': wrong_id,
            'result': self.post_result
        })
        post_mock.return_value = post_response
        block_number = 123456789

        client = RskClient(self.url)
        with self.assertRaises(RskClientError) as e:
            client.get_block_by_number(block_number)

        expected_call = [call(self.url,
                              data=json.dumps({
                                  "jsonrpc": "2.0",
                                  "id": self.request_id,
                                  "method": "eth_getBlockByNumber",
                                  "params": [hex(block_number), False],
                              }),
                              headers={"content-type": "application/json"})]

        self.assertEqual(expected_call, post_mock.call_args_list)
        self.assertEqual("While getting the block by number: While calling the "
                         "'eth_getBlockByNumber' method: Unexpected response "
                         f"id {wrong_id} (expecting {self.request_id})",
                         str(e.exception))
