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

class Platform:
    LEDGER = "Ledger"
    SGX = "SGX"
    X86 = "X86"
    VALID_PLATFORMS = [LEDGER, SGX, X86]

    MESSAGES = {
        LEDGER: {
            "restart": "disconnect and re-connect the ledger nano",
        },
        SGX: {
            "restart": "restart the SGX powHSM",
        },
        X86: {
            "restart": "restart the TCPSigner",
        }
    }

    _platform = None
    _options = None

    @classmethod
    def set(klass, plf, options={}):
        if plf not in klass.VALID_PLATFORMS:
            raise RuntimeError("Invalid platform given")
        klass._platform = plf
        klass._options = options

    @classmethod
    def is_ledger(klass):
        return klass._platform == Platform.LEDGER

    @classmethod
    def is_sgx(klass):
        return klass._platform == Platform.SGX

    @classmethod
    def options(klass, key):
        return klass._options[key]

    @classmethod
    def message(klass, key):
        return klass.MESSAGES[klass._platform][key]
