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

import os
from ledger.hsm2dongle import HSM2Dongle
from mgr.runner import ManagerRunner
from ledger.pin import FileBasedPin
from user.options import UserOptionParser


def load_pin(user_options):
    env_pin = os.environ.get("PIN", None)
    if env_pin is not None:
        env_pin = env_pin.encode()
    pin = FileBasedPin(
        user_options.pin_file,
        default_pin=env_pin,
        force_change=user_options.force_pin_change,
    )
    return pin


if __name__ == "__main__":
    user_options = UserOptionParser("Start the powHSM manager",
                                    with_pin=True).parse()

    runner = ManagerRunner("powHSM manager",
                           lambda options: HSM2Dongle(options.dongle_debug),
                           load_pin)

    runner.run(user_options)
