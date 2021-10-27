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

from argparse import ArgumentParser
import socket
import sys
import json
from math import ceil

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 9999
DEFAULT_VERBOSE = False
CHUNK_PLACEHOLDER = "<CHUNK>"

parser = ArgumentParser(description="Send a request to the powHSM manager")
parser.add_argument(
    "-a",
    "--host",
    dest="host",
    help="destination host (default %s)" % DEFAULT_HOST,
    type=str,
    default=DEFAULT_HOST,
)
parser.add_argument(
    "-p",
    "--port",
    dest="port",
    help="destination port (default %d)" % DEFAULT_PORT,
    type=int,
    default=DEFAULT_PORT,
)
parser.add_argument(
    "-v",
    "--verbose",
    dest="verbose",
    help="print server address and sent data (default %s)" % DEFAULT_VERBOSE,
    default=DEFAULT_VERBOSE,
    action="store_const",
    const=True,
)
parser.add_argument(
    "-c",
    "--command",
    dest="command",
    help="command blueprint to send. used to send data in chunks. use chunk placeholder "
         "'%s'. when using this, the 'data' parameter is the path to a JSON file "
         "containing the data to send."
    % CHUNK_PLACEHOLDER,
)
parser.add_argument(
    "-s",
    "--chunksize",
    dest="chunksize",
    help="size of the chunks to send. must be used alongside '-c'",
    type=int,
)
parser.add_argument(
    "-o",
    "--chunkoverlap",
    dest="chunkoverlap",
    help="send the last block of the previous chunk as the first block of the next one. "
         "must be used alongside '-c'",
    action="store_const",
    const=True,
)
parser.add_argument("data", type=str, help="the data to send (only when not using '-c')")
options = parser.parse_args()

if options.command is not None:
    if options.chunksize is None:
        print("Must specify a chunk size with '-s' or '--chunksize'")
        sys.exit(-1)

    # Assuming the whole file fits in memory
    try:
        with open(options.data, "r") as datafile:
            data = json.load(datafile)
    except Exception as e:
        print("Error loading data from JSON file '%s': %s" % (options.data, str(e)))
        sys.exit(-2)

    # Validate data
    if type(data) != list or len(data) == 0:
        print("Invalid or empty data file '%s'" % options.data)
        sys.exit(-2)

    # Calculate chunks
    chunks = []
    for chunk_index in range(ceil(len(data)/options.chunksize)):
        start_offset = -1 if options.chunkoverlap and chunk_index > 0 else 0
        chunk_data = data[chunk_index*options.chunksize +
                          start_offset:chunk_index*options.chunksize + options.chunksize]
        chunks.append(options.command.replace(CHUNK_PLACEHOLDER, json.dumps(chunk_data)))
    print("Data size: %d; total chunks: %d; chunk size: %d" %
          (len(data), len(chunks), options.chunksize))

else:
    chunks = [options.data]

if options.verbose:
    print("Server:   %s:%s" % (options.host, options.port))

total_chunks = len(chunks)
for chunk_index, chunk in enumerate(chunks):
    if options.verbose:
        print("Sending chunk %d/%d:     %s" % (chunk_index + 1, total_chunks, chunk))
    else:
        print("Sending chunk %d/%d..." % (chunk_index + 1, total_chunks))

    # Connect to server and send chunk
    # (protocol is in the HTTP/1.0 style - one command per connection,
    # cannot reuse socket objects)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((options.host, options.port))
        sock.sendall(bytes(chunk + "\n", "utf-8"))

        # Receive data from the server
        received = str(sock.recv(1024**2), "utf-8")

    print("Received: %s" % received.strip())
