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

from .misc import info, head, get_hsm, dispose_hsm, AdminError
from .unlock import do_unlock
from .signer_authorization import SignerAuthorization


def do_authorize_signer(options):
    head("### -> Authorize signer", fill="#")
    hsm = None

    # Require a signer authorization file
    if options.signer_authorization_file_path is None:
        raise AdminError("No signer authorization file path given")

    # Load the given signer authorization
    try:
        signer_authorization = SignerAuthorization.from_jsonfile(
            options.signer_authorization_file_path)
    except Exception as e:
        raise AdminError(f"While loading the signer authorization file: {str(e)}")

    # Attempt to unlock the device without exiting the UI
    try:
        do_unlock(options, label=False, exit=False)
    except Exception as e:
        raise AdminError(f"Failed to unlock device: {str(e)}")

    # Signer authorization
    hsm = None
    info("Authorising signer... ", options.verbose)
    try:
        hsm = get_hsm(options.verbose)
        hsm.authorize_signer(signer_authorization)
    except Exception as e:
        raise AdminError(f"Failed to authorize signer: {str(e)}")
    finally:
        dispose_hsm(hsm)

    info("Signer authorized")
