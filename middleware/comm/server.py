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

import socketserver
import threading
import socket
import json
import logging
from comm.protocol import HSM2ProtocolError, HSM2ProtocolInterrupt

LOGGER_NAME = "srver"


class RequestHandlerError(RuntimeError):
    pass


class RequestHandlerShutdown(RuntimeError):
    pass


class _RequestHandler:
    ENCODING = "utf-8"

    def __init__(self, protocol, logger):
        self.protocol = protocol
        self.logger = logger

    def handle(self, client_address, rfile, wfile):
        try:
            line = rfile.readline().strip()
            data = line.decode(self.ENCODING)
        except UnicodeDecodeError:
            output = json.dumps(self.protocol.format_error(), sort_keys=True)
            self.logger.info(
                "<= [%s]: invalid encoding input - 0x%s", client_address, line.hex()
            )
            self.logger.info("=> [%s]: %s", client_address, output)
            self._reply(wfile, output)
            return

        self.logger.info("<= [%s]: %s", client_address, data)
        try:
            response = {}
            request = json.loads(data)
            self.logger.debug("Delivering request")
            response = self.protocol.handle_request(request)
            self.logger.debug("Got response: %s", response)
        except json.decoder.JSONDecodeError as e:
            self.logger.debug("JSON error: %s", e)
            response = self.protocol.format_error()
        except NotImplementedError as e:
            self.logger.critical("Not implemented: %s", e)
        except HSM2ProtocolError as e:
            response = self.protocol.unknown_error()
            raise RequestHandlerError(format(e))
        except HSM2ProtocolInterrupt as e:
            raise RequestHandlerShutdown(format(e))
        except Exception as e:
            message = "Unknown exception while handling request: %s" % format(e)
            self.logger.critical(message)
            raise RequestHandlerError(message)
        finally:
            output = json.dumps(response, sort_keys=True)
            self.logger.info("=> [%s]: %s", client_address, output)
            self._reply(wfile, output)

    def _reply(self, wfile, output):
        try:
            wfile.write(output.encode(self.ENCODING))
            wfile.write("\n".encode(self.ENCODING))
        except Exception as e:
            self.logger.warning("Error replying: %s", str(e))


class _TCPServerRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            handler = _RequestHandler(self.server.protocol, self.server.logger)
            handler.handle(self.client_address[0], self.rfile, self.wfile)
        except RequestHandlerError as e:
            # Log the error and shutdown
            self.server.logger.critical("Error handling request: %s", format(e))
            self.shutdown()
        except RequestHandlerShutdown as e:
            # A shutdown has been requested, log and shutdown
            self.server.logger.info("Shutting down: %s", format(e))
            self.shutdown()
        except Exception as e:
            # Any unknown exception should also trigger a shutdown
            self.server.logger.critical("UNKNOWN error serving request: %s", format(e))
            self.shutdown()

    def shutdown(self):
        def tgt():
            return self._do_shutdown()

        threading.Thread(target=tgt).start()

    def _do_shutdown(self):
        self.server.shutdown()


class TCPServerError(RuntimeError):
    pass


class TCPServer:
    def __init__(self, host, port, protocol):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.logger = logging.getLogger(LOGGER_NAME)
        self.server = None

    def run(self):
        try:
            self.logger.info("Initializing device")
            self.protocol.initialize_device()
            self.logger.info("Initializing server")
            socketserver.TCPServer.allow_reuse_address = True
            self.server = socketserver.TCPServer(
                (self.host, self.port), _TCPServerRequestHandler
            )
            self.server.protocol = self.protocol
            self.server.logger = self.logger
            self.logger.info("Listening on %s:%d" % (self.host, self.port))
            self.server.serve_forever()
        except socket.error as e:
            message = "Error running server: %s" % format(e)
            self.logger.critical(message)
            raise TCPServerError(message)
        except NotImplementedError as e:
            message = "Not implemented: %s" % format(e)
            self.logger.critical(message)
            raise TCPServerError(message)
        except KeyboardInterrupt:
            self.logger.info("Interrupted by user!")
        except HSM2ProtocolInterrupt:
            self.logger.info("Interrupted by HSM2 protocol!")
        except HSM2ProtocolError as e:
            message = "Error in device initialization: %s" % format(e)
            self.logger.critical(message)
            raise TCPServerError(message)
        finally:
            if self.server is not None:
                self.logger.info("Terminating server")
                self.server.server_close()
