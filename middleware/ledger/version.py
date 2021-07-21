# Instances of this represent firmware versions
# of firmware installed on an HSM2
# A version consists of a major, minor and patch
class HSM2FirmwareVersion:
    def __init__(self, major, minor, patch):
        self.major = major
        self.minor = minor
        self.patch = patch

    def __str__(self):
        return "v%d.%d.%d" % (self.major, self.minor, self.patch)

    def is_compliant_with(self, wanted_version):
        return self.major == wanted_version.major and\
                self.minor >= wanted_version.minor and\
                (self.minor > wanted_version.minor or self.patch >= wanted_version.patch)
