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

def get_utilities():
    return {
        "load": "loadApp",
        "delete": "deleteApp",
        "setupCA": "setupCustomCA",
        "resetCA": "resetCustomCA",
        "genCA": "genCAPair",
    }


def parse_args(argv):
    utilities = get_utilities()

    if len(argv) < 2 or argv[1] not in utilities:
        commands = ", ".join(utilities.keys())
        print("Ledgerblue utilities")
        print(f"usage: {argv[0]} {{{commands}}} [options]")
        sys.exit(99)

    module = f"ledgerblue.{utilities[argv[1]]}"
    sys_argv = [f"{argv[0]} {argv[1]}"] + argv[2:]

    return module, sys_argv


if __name__ == "__main__":
    import runpy
    import sys

    module, sys.argv = parse_args(sys.argv)

    try:
        res = runpy.run_module(module, run_name="__main__")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
