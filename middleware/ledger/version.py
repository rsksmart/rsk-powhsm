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

# Instances of this represent firmware versions
# of firmware installed on a powHSM.
# It is also used to represent implemented versions
# of the powHSM protocol on the middleware manager.
# A version consists of a major, minor and patch
class HSM2FirmwareVersion:
    def __init__(self, major, minor, patch):
        self.major = major
        self.minor = minor
        self.patch = patch

    def __str__(self):
        return "v%d.%d.%d" % (self.major, self.minor, self.patch)

    def __repr__(self):
        return f"HSM2FirmwareVersion<{str(self)[1:]}>"

    # This returns true iff this version's
    # middleware protocol is compatible
    # with the given firmware running version.
    #
    # Declaratively, middleware and firmware major versions must be always equal,
    # but middleware's <minor, patch> version must be greater or equal than
    # that of the firmware's.
    def supports(self, running_version):
        return (
            self.major == running_version.major
            and self.minor >= running_version.minor
            and (
                self.minor > running_version.minor or self.patch >= running_version.patch
            )
        )

    # This returns true iff this version is
    # greater or equal than the given version
    # (the implementation is the same as that
    # of the 'supports' method, but the semantics
    # are different)
    def __ge__(self, other):
        return self.supports(other)

    # Self explanatory
    def __eq__(self, other):
        return (
            self.major == other.major
            and self.minor == other.minor
            and self.patch == other.patch
        )
