from unittest import TestCase
from parameterized import parameterized
from ledger.version import HSM2FirmwareVersion

import logging
logging.disable(logging.CRITICAL)

class TestHSM2FirmwareVersion(TestCase):
    @parameterized.expand([
        ("same_version", (1,1,0), (1,1,0), True),
        ("firmware_higher_minor", (1,1,0), (1,2,5), False),
        ("firmware_lower_minor", (1,1,0), (1,0,5), True),
        ("firmware_lower_minor_higher_patch", (2,5,0), (2,4,3), True),
        ("different_major_same_minor_patch", (2,5,5), (3,5,5), False),
        ("different_major_same_minor_patch", (2,5,5), (3,5,5), False),
    ])
    def test_supports(self, _, mware_version_t, firmware_version_t, should_be_supported):
      mware_version = HSM2FirmwareVersion(mware_version_t[0], mware_version_t[1], mware_version_t[2])
      firmware_version = HSM2FirmwareVersion(firmware_version_t[0], firmware_version_t[1], firmware_version_t[2])
      self.assertEqual(should_be_supported, mware_version.supports(firmware_version))

    @parameterized.expand([
        ("same_version", (1,1,0), (1,1,0), True),
        ("firmware_higher_minor", (1,1,0), (1,2,5), False),
        ("firmware_lower_minor", (1,1,0), (1,0,5), True),
        ("firmware_lower_minor_higher_patch", (2,5,0), (2,4,3), True),
        ("different_major_same_minor_patch", (2,5,5), (3,5,5), False),
        ("different_major_same_minor_patch", (2,5,5), (3,5,5), False),
    ])
    def test_greater_or_equal(self, _, version_a_t, version_b_t, is_geq):
      version_a = HSM2FirmwareVersion(version_a_t[0], version_a_t[1], version_a_t[2])
      version_b = HSM2FirmwareVersion(version_b_t[0], version_b_t[1], version_b_t[2])
      self.assertEqual(is_geq, version_a >= version_b)

    @parameterized.expand([
        ("same_version", (1,2,3), (1,2,3), True),
        ("different_major", (1,2,3), (7,2,3), False),
        ("different_minor", (1,2,3), (1,4,3), False),
        ("different_patch", (1,2,3), (1,2,5), False),
    ])
    def test_equal(self, _, version_a_t, version_b_t, is_eq):
      version_a = HSM2FirmwareVersion(version_a_t[0], version_a_t[1], version_a_t[2])
      version_b = HSM2FirmwareVersion(version_b_t[0], version_b_t[1], version_b_t[2])
      self.assertEqual(is_eq, version_a == version_b)