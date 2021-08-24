from unittest import TestCase
from ledger.version import HSM2FirmwareVersion

import logging
logging.disable(logging.CRITICAL)

class TestHSM2FirmwareVersion(TestCase):
    def test_is_compliant_with(self):
        for tc in [  # Version, wanted version, expected compliant
                    ((1,1,0), (1,1,0), True), # Same version
                    ((1,1,0), (1,2,5), False), # Wanted a higher minor
                    ((1,1,0), (1,0,5), True), # Wanted a lower minor
                    ((2,5,0), (2,4,3), True), # Lower minor with higher patch
                    ((2,5,5), (3,5,5), False), # Different major, same minor & patch
                  ]:
            versiona = HSM2FirmwareVersion(tc[0][0], tc[0][1], tc[0][2])
            versionb = HSM2FirmwareVersion(tc[1][0], tc[1][1], tc[1][2])
            self.assertEqual(tc[2], versiona.is_compliant_with(versionb))
