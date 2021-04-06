# Instances of this represent firmware versions
# of firmware installed on an HSM2.
# It is also used to represent implemented versions
# of the HSM2 protocol on the middleware manager.
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
        return self.major == running_version.major and\
                self.minor >= running_version.minor and\
                (self.minor > running_version.minor or self.patch >= running_version.patch)

    # This returns true iff this version is
    # greater or equal than the given version
    # (the implementation is the same as that
    # of the 'supports' method, but the semantics
    # are different)
    def __ge__(self, other):
        return self.supports(other)

    # Self explanatory
    def __eq__(self, other):
        return self.major == other.major and\
                self.minor == other.minor and\
                self.patch == other.patch
