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

from unittest import TestCase
from parameterized import parameterized
from comm.cstruct import CStruct

import logging

logging.disable(logging.CRITICAL)


class RandomBisStruct(CStruct):
    """
    random_bis_t

    uint16_t another_double
    uint8_t single_arr 10
    uint32_t another_quad
    """


class RandomTrisStruct(CStruct):
    """
    random_tris_t

    uint8_t arr_one 2
    uint8_t arr_two 3
    """


class RandomStruct(CStruct):
    """
    random_t

    uint8_t  single_val
    uint16_t double_val
    uint32_t quad_val
    uint64_t oct_val

    random_bis_t  other_random
    random_tris_t yet_other_random
    """


class Invalid1(CStruct):
    """
    invalid_1

    nonexistent_type something
    """


class Invalid2(CStruct):
    """
    invalid_2

    uint32_t withlength 5
    """


class ValidWithInvalid(CStruct):
    """
    valid_with_invalid

    uint8_t a_number
    uint16_t another_number
    invalid_2 something_invalid
    """


class TestCStruct(TestCase):
    def setUp(self):
        self.packed = bytes.fromhex(
            "99"  # single_val
            "0102"  # double_val
            "03040506"  # quad_val
            "0708090a0b0c0d0e"  # oct_val
            "8899"  # another_double
            "00112233445566778899"  # single_arr
            "d1d2d3d4"  # another_quad
            "aabb"  # arr_one
            "ccddee"  # arr_two
        )

    def test_expected_sizes(self):
        self.assertEqual(16, RandomBisStruct.get_bytelength())
        self.assertEqual(5, RandomTrisStruct.get_bytelength())
        self.assertEqual(15 +
                         RandomBisStruct.get_bytelength() +
                         RandomTrisStruct.get_bytelength(),
                         RandomStruct.get_bytelength())

    def test_parsing_default(self):
        parsed = RandomStruct(self.packed)

        self.assertEqual(0x99, parsed.single_val)
        self.assertEqual(0x0201, parsed.double_val)
        self.assertEqual(0x06050403, parsed.quad_val)
        self.assertEqual(0x0e0d0c0b0a090807, parsed.oct_val)

        self.assertEqual(0x9988, parsed.other_random.another_double)
        self.assertEqual(bytes.fromhex("00112233445566778899"),
                         parsed.other_random.single_arr)
        self.assertEqual(0xd4d3d2d1, parsed.other_random.another_quad)

        self.assertEqual(bytes.fromhex("aabb"), parsed.yet_other_random.arr_one)
        self.assertEqual(bytes.fromhex("ccddee"), parsed.yet_other_random.arr_two)

        self.assertEqual({
            "single_val": 0x99,
            "double_val": 0x0201,
            "quad_val": 0x06050403,
            "oct_val": 0x0e0d0c0b0a090807,
            "other_random": {
                "another_double": 0x9988,
                "single_arr": "00112233445566778899",
                "another_quad": 0xd4d3d2d1,
            },
            "yet_other_random": {
                "arr_one": "aabb",
                "arr_two": "ccddee",
            }
        }, parsed.to_dict())

    def test_parsing_little_offset(self):
        parsed = RandomStruct(b"thisisrandom" + self.packed, offset=12, little=True)

        self.assertEqual(0x99, parsed.single_val)
        self.assertEqual(0x0201, parsed.double_val)
        self.assertEqual(0x06050403, parsed.quad_val)
        self.assertEqual(0x0e0d0c0b0a090807, parsed.oct_val)

        self.assertEqual(0x9988, parsed.other_random.another_double)
        self.assertEqual(bytes.fromhex("00112233445566778899"),
                         parsed.other_random.single_arr)
        self.assertEqual(0xd4d3d2d1, parsed.other_random.another_quad)

        self.assertEqual(bytes.fromhex("aabb"), parsed.yet_other_random.arr_one)
        self.assertEqual(bytes.fromhex("ccddee"), parsed.yet_other_random.arr_two)

        self.assertEqual({
            "single_val": 0x99,
            "double_val": 0x0201,
            "quad_val": 0x06050403,
            "oct_val": 0x0e0d0c0b0a090807,
            "other_random": {
                "another_double": 0x9988,
                "single_arr": "00112233445566778899",
                "another_quad": 0xd4d3d2d1,
            },
            "yet_other_random": {
                "arr_one": "aabb",
                "arr_two": "ccddee",
            }
        }, parsed.to_dict())

    def test_parsing_big(self):
        parsed = RandomStruct(self.packed, little=False)

        self.assertEqual(0x99, parsed.single_val)
        self.assertEqual(0x0102, parsed.double_val)
        self.assertEqual(0x03040506, parsed.quad_val)
        self.assertEqual(0x0708090a0b0c0d0e, parsed.oct_val)

        self.assertEqual(0x8899, parsed.other_random.another_double)
        self.assertEqual(bytes.fromhex("00112233445566778899"),
                         parsed.other_random.single_arr)
        self.assertEqual(0xd1d2d3d4, parsed.other_random.another_quad)

        self.assertEqual(bytes.fromhex("aabb"), parsed.yet_other_random.arr_one)
        self.assertEqual(bytes.fromhex("ccddee"), parsed.yet_other_random.arr_two)

        self.assertEqual({
            "single_val": 0x99,
            "double_val": 0x0102,
            "quad_val": 0x03040506,
            "oct_val": 0x0708090a0b0c0d0e,
            "other_random": {
                "another_double": 0x8899,
                "single_arr": "00112233445566778899",
                "another_quad": 0xd1d2d3d4,
            },
            "yet_other_random": {
                "arr_one": "aabb",
                "arr_two": "ccddee",
            }
        }, parsed.to_dict())

    def test_parsing_toosmall(self):
        with self.assertRaises(ValueError):
            RandomStruct(b"thisistoosmall")

    @parameterized.expand([
        ("invalid_one", Invalid1),
        ("invalid_two", Invalid2),
        ("valid_with_invalid", ValidWithInvalid)
    ])
    def test_invalid_spec(self, _, kls):
        with self.assertRaises(ValueError):
            kls.get_bytelength()

        with self.assertRaises(ValueError):
            kls(b'somethingtoparse')
