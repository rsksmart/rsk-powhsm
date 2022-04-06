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
from unittest.mock import Mock, call, ANY, patch
from comm.server import (
    TCPServer,
    TCPServerError,
    _RequestHandler,
    RequestHandlerError,
    RequestHandlerShutdown,
)
from comm.protocol import HSM2ProtocolError, HSM2ProtocolInterrupt
import socketserver
import socket

import logging

logging.disable(logging.CRITICAL)


class TestTCPServer(TestCase):
    def setUp(self):
        self.protocol = Mock()
        self.server = TCPServer("a-host", 1234, self.protocol)

    def test_init_ok(self):
        self.assertEqual(self.server.host, "a-host")
        self.assertEqual(self.server.port, 1234)
        self.assertEqual(self.server.protocol, self.protocol)

    @patch("socketserver.TCPServer")
    def test_run_ok(self, TCPServerMock):
        TCPServerMock.return_value = Mock()

        self.server.run()

        self.assert_server_setup_ok(TCPServerMock)

        self.assertEqual(self.server.server.serve_forever.call_count, 1)
        self.assertEqual(self.server.server.server_close.call_count, 1)

    @patch("socketserver.TCPServer")
    def test_run_interrupt(self, TCPServerMock):
        TCPServerMock.return_value = Mock()
        TCPServerMock.return_value.serve_forever = Mock(side_effect=KeyboardInterrupt)

        self.server.run()

        self.assert_server_setup_ok(TCPServerMock)

        self.assertEqual(self.server.server.serve_forever.call_count, 1)
        self.assertEqual(self.server.server.server_close.call_count, 1)

    @patch("socketserver.TCPServer")
    def test_run_socket_error(self, TCPServerMock):
        TCPServerMock.return_value = Mock()
        TCPServerMock.return_value.serve_forever = Mock(side_effect=socket.error)

        with self.assertRaises(TCPServerError):
            self.server.run()

        self.assert_server_setup_ok(TCPServerMock)

        self.assertEqual(self.server.server.serve_forever.call_count, 1)
        self.assertEqual(self.server.server.server_close.call_count, 1)

    @patch("socketserver.TCPServer")
    def test_run_initialize_device_not_implemented(self, TCPServerMock):
        TCPServerMock.return_value = Mock()
        self.protocol.initialize_device.side_effect = NotImplementedError()

        with self.assertRaises(TCPServerError):
            self.server.run()

        self.assertEqual(self.protocol.initialize_device.call_args, [call()])
        self.assertIsNone(self.server.server)

    def assert_server_setup_ok(self, TCPServerMock):
        self.assertEqual(TCPServerMock.call_args_list, [call(("a-host", 1234), ANY)])
        self.assertEqual(self.server.server, TCPServerMock.return_value)
        self.assertEqual(self.server.server.protocol, self.protocol)
        self.assertEqual(self.protocol.initialize_device.call_args, [call()])


class TestTCPServerRequestHandler(TestCase):
    @patch("socketserver.TCPServer")
    @patch("comm.server._RequestHandler")
    def setUp(self, RequestHandlerMock, TCPServerMock):
        self.protocol = Mock()
        self.server = TCPServer("a-host", 1234, self.protocol)
        TCPServerMock.return_value = Mock()
        self.server.run()
        self.handler = TCPServerMock.call_args[0][1]
        self.handler_instance = Mock()
        self.handler_instance.server = TCPServerMock.return_value
        self.handler_instance.client_address = ("a-client-address", )
        self.handler_instance.rfile = "an-rfile"
        self.handler_instance.wfile = "an-wfile"
        self.request_handler = Mock()
        self.RequestHandlerMock = RequestHandlerMock
        RequestHandlerMock.return_value = self.request_handler
        self.handler.handle(self.handler_instance)

    def test_handles_ok(self):
        self.assertEqual(
            self.RequestHandlerMock.call_args_list,
            [call(self.protocol, self.server.logger)],
        )
        self.assertEqual(
            self.request_handler.handle.call_args_list,
            [call("a-client-address", "an-rfile", "an-wfile")],
        )

    def test_handler_correct_subclass(self):
        self.assertTrue(issubclass(self.handler, socketserver.StreamRequestHandler))


class TestRequestHandler(TestCase):
    def setUp(self):
        self.protocol = Mock()
        self.logger = Mock()
        self.handler = _RequestHandler(self.protocol, self.logger)
        self.rfile = Mock()
        self.wfile = Mock()

    def test_logger_protocol(self):
        self.assertEqual(self.protocol, self.handler.protocol)
        self.assertEqual(self.logger, self.handler.logger)

    def test_handler_correct_encoding(self):
        self.assertEqual(self.handler.ENCODING, "utf-8")

    def test_handle_ok(self):
        self.mock_request('{"this-is": "legal", "json": "format"}')
        self.protocol.handle_request.return_value = {"this": "is", "the": "result"}

        self.do_request()

        self.assertEqual(
            self.protocol.handle_request.call_args_list,
            [call({
                "this-is": "legal",
                "json": "format"
            })],
        )
        self.assertEqual(
            self.wfile.write.call_args_list,
            [
                call('{"the": "result", "this": "is"}'.encode("utf-8")),
                call("\n".encode("utf-8")),
            ],
        )

    def test_handle_broken_pipe_reply(self):
        self.mock_request('{"this-is": "legal", "json": "format"}')
        self.protocol.handle_request.return_value = {"this": "is", "the": "result"}
        self.wfile.write.side_effect = BrokenPipeError()

        self.do_request()

        self.assertEqual(
            self.protocol.handle_request.call_args_list,
            [call({
                "this-is": "legal",
                "json": "format"
            })],
        )
        self.assertEqual(
            self.wfile.write.call_args_list,
            [call('{"the": "result", "this": "is"}'.encode("utf-8"))],
        )

    def test_handle_json_error(self):
        self.mock_request("this-is-not-json")
        self.protocol.format_error.return_value = {"format": "error", "a": "bad"}

        self.do_request()

        self.assertFalse(self.protocol.handle_request.called)
        self.assertEqual(
            self.wfile.write.call_args_list,
            [
                call('{"a": "bad", "format": "error"}'.encode("utf-8")),
                call("\n".encode("utf-8")),
            ],
        )

    def test_handle_notimplemented_error(self):
        self.mock_request('{"another": "valid", "json": "request"}')
        self.protocol.handle_request.side_effect = NotImplementedError(
            "method not implemented")

        self.do_request()

        self.assertEqual(
            self.protocol.handle_request.call_args_list,
            [call({
                "another": "valid",
                "json": "request"
            })],
        )
        self.assertEqual(
            self.wfile.write.call_args_list,
            [call("{}".encode("utf-8")),
             call("\n".encode("utf-8"))],
        )

    def test_handle_protocol_error(self):
        self.mock_request('{"another": "valid", "json": "request"}')
        self.protocol.unknown_error.return_value = {"an": "unknown", "e": "rror"}
        self.protocol.handle_request.side_effect = HSM2ProtocolError("protocol error")

        with self.assertRaises(RequestHandlerError):
            self.do_request()

        self.assertEqual(
            self.protocol.handle_request.call_args_list,
            [call({
                "another": "valid",
                "json": "request"
            })],
        )
        self.assertEqual(
            self.wfile.write.call_args_list,
            [
                call('{"an": "unknown", "e": "rror"}'.encode("utf-8")),
                call("\n".encode("utf-8")),
            ],
        )

    def test_handle_protocol_shutdown(self):
        self.mock_request('{"another": "valid", "json": "request"}')
        self.protocol.handle_request.side_effect = HSM2ProtocolInterrupt(
            "protocol interrupt")

        with self.assertRaises(RequestHandlerShutdown):
            self.do_request()

        self.assertEqual(
            self.protocol.handle_request.call_args_list,
            [call({
                "another": "valid",
                "json": "request"
            })],
        )
        self.assertEqual(
            self.wfile.write.call_args_list,
            [call("{}".encode("utf-8")),
             call("\n".encode("utf-8"))],
        )

    def test_handle_unknown_exception(self):
        self.mock_request('{"another": "valid", "json": "request"}')
        self.protocol.handle_request.side_effect = ValueError("unexpected")

        with self.assertRaises(RequestHandlerError):
            self.do_request()

        self.assertEqual(
            self.protocol.handle_request.call_args_list,
            [call({
                "another": "valid",
                "json": "request"
            })],
        )
        self.assertEqual(
            self.wfile.write.call_args_list,
            [call("{}".encode("utf-8")),
             call("\n".encode("utf-8"))],
        )

    def test_handle_invalid_encoding(self):
        self.rfile.readline.return_value = b"\xff\xfa\xf0"
        self.protocol.format_error.return_value = {"encoding": "error", "a": "bad"}

        self.do_request()

        self.assertFalse(self.protocol.handle_request.called)
        self.assertEqual(
            self.wfile.write.call_args_list,
            [
                call('{"a": "bad", "encoding": "error"}'.encode("utf-8")),
                call("\n".encode("utf-8")),
            ],
        )

    def test_handle_invalid_encoding_broken_pipe(self):
        self.rfile.readline.return_value = b"\xff\xfa\xf0"
        self.protocol.format_error.return_value = {"encoding": "error", "a": "bad"}
        self.wfile.write.side_effect = BrokenPipeError()

        self.do_request()

        self.assertFalse(self.protocol.handle_request.called)
        self.assertEqual(
            self.wfile.write.call_args_list,
            [call('{"a": "bad", "encoding": "error"}'.encode("utf-8"))],
        )

    def mock_request(self, line):
        self.rfile.readline.return_value = line.encode("utf-8")

    def do_request(self):
        self.handler.handle("an-address", self.rfile, self.wfile)
