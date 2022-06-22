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
from unittest.mock import call, patch
from admin.rsk_client import RskClient, RskClientError

import json


@patch("requests.post")
class TestRskClient(TestCase):
    def setUp(self):
        self.force_wrong_id = False

    def generate_post_response(self, url, headers, data):
        self.request_id = json.loads(data)['id']
        if self.force_wrong_id:
            self.request_id = self.request_id + 1
        response = SimpleNamespace()
        response.status_code = self.status_code
        response.text = json.dumps({
            'id': self.request_id,
            'result': 'aa' * 65
        })

        return response

    def test_get_best_block_number(self, post_mock):
        post_mock.side_effect = self.generate_post_response
        self.status_code = 200
        client = RskClient('an-url')
        best_block = client.get_best_block_number()
        self.assertEqual([call('an-url',
                               data=json.dumps({
                                   "jsonrpc": "2.0",
                                   "id": self.request_id,
                                   "method": "eth_blockNumber",
                                   "params": []
                               }),
                               headers={
                                   'content-type': 'application/json'
                               })], post_mock.call_args_list)
        self.assertEqual(int('aa' * 65, 16), best_block)

    def test_get_best_block_number_server_error(self, post_mock):
        post_mock.side_effect = self.generate_post_response
        self.status_code = 400
        client = RskClient('an-url')
        with self.assertRaises(RskClientError):
            client.get_best_block_number()
        self.assertEqual([call('an-url',
                               data=json.dumps({
                                   "jsonrpc": "2.0",
                                   "id": self.request_id,
                                   "method": "eth_blockNumber",
                                   "params": []
                               }),
                               headers={
                                   'content-type': 'application/json'
                               })], post_mock.call_args_list)

    def test_get_best_block_number_id_error(self, post_mock):
        post_mock.side_effect = self.generate_post_response
        self.status_code = 200
        self.force_wrong_id = True
        client = RskClient('an-url')
        with self.assertRaises(RskClientError):
            client.get_best_block_number()
        self.assertEqual([call('an-url',
                               data=json.dumps({
                                   "jsonrpc": "2.0",
                                   "id": self.request_id - 1,
                                   "method": "eth_blockNumber",
                                   "params": []
                               }),
                               headers={
                                   'content-type': 'application/json'
                               })], post_mock.call_args_list)

    def test_get_block_by_number(self, post_mock):
        post_mock.side_effect = self.generate_post_response
        self.status_code = 200
        block_number = 123456789
        client = RskClient('an-url')
        best_block = client.get_block_by_number(block_number)

        self.assertEqual([call('an-url',
                               data=json.dumps({
                                   "jsonrpc": "2.0",
                                   "id": self.request_id,
                                   "method": "eth_getBlockByNumber",
                                   "params": [hex(block_number), False],
                               }),
                               headers={"content-type": "application/json"})],
                         post_mock.call_args_list)
        self.assertEqual('aa' * 65, best_block)

    def test_get_block_by_number_server_error(self, post_mock):
        post_mock.side_effect = self.generate_post_response
        self.status_code = 400
        block_number = 123456789
        client = RskClient('an-url')
        with self.assertRaises(RskClientError):
            client.get_block_by_number(block_number)

        self.assertEqual([call('an-url',
                               data=json.dumps({
                                   "jsonrpc": "2.0",
                                   "id": self.request_id,
                                   "method": "eth_getBlockByNumber",
                                   "params": [hex(block_number), False],
                               }),
                               headers={"content-type": "application/json"})],
                         post_mock.call_args_list)

    def test_get_block_by_number_id_error(self, post_mock):
        post_mock.side_effect = self.generate_post_response
        self.status_code = 200
        self.force_wrong_id = True
        block_number = 123456789
        client = RskClient('an-url')

        with self.assertRaises(RskClientError):
            client.get_block_by_number(block_number)

        self.assertEqual([call('an-url',
                               data=json.dumps({
                                   "jsonrpc": "2.0",
                                   "id": self.request_id - 1,
                                   "method": "eth_getBlockByNumber",
                                   "params": [hex(block_number), False],
                               }),
                               headers={"content-type": "application/json"})],
                         post_mock.call_args_list)
