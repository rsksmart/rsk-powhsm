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
from admin.misc import AdminError
from elftools.elf.elffile import ELFFile
import json
from sgx.sgxtypes.sgx_enclave_properties import EnclaveProperties


class EnclaveBinary:

    def __init__(self, enclave_path):
        self.enclave_path = enclave_path

    def load_binary(self):
        self.enclave_properties = None
        try:
            with open(self.enclave_path, "rb") as f:
                elf = ELFFile(f)
                oeinfo = elf.get_section_by_name(".oeinfo")
                if oeinfo is not None:
                    self.enclave_properties = EnclaveProperties(oeinfo.data())
        except Exception as e:
            raise AdminError(f"Failed to load enclave binary: {e}")
        if self.enclave_properties is None:
            raise AdminError("Enclave binary does not contain .oeinfo section")

    def get_mrenclave(self):
        return self.enclave_properties.get_mrenclave()


def main():
    parser = ArgumentParser(description="powHSM MRENCLAVE extractor")
    parser.add_argument(
        "-e",
        "--enclave",
        dest="enclave_path",
        help="Path to the signed enclave binary",
        required=True,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        help="Print verbose output",
        action="store_true",
    )
    args = parser.parse_args()
    enclave_binary = EnclaveBinary(args.enclave_path)
    try:
        enclave_binary.load_binary()
        mrenclave = enclave_binary.get_mrenclave()
        if args.verbose:
            print(json.dumps(enclave_binary.enclave_properties.to_dict(), indent=4))
        print(f"MRENCLAVE: {mrenclave}")
    except AdminError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
