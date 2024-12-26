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

TEST_PUBKEYS_JSON = """
{
    "m/44'/1'/0'/0/0": "04abe31ee7c91976f7a56d8e196d82d5ce75a0fcc2935723bf25610d22bd81e50fb4def0b3f99ae2054868ea2133e5b88145220ac492f86b942bd40f574d9117e1",
    "m/44'/1'/1'/0/0": "04d44eac557a58be6cd4a40cbdaa9ed22cf4f0322e8c7bb84f6421d5bdda3b99ff73982e67c4550faad3f67de7615a0a32cfcf3322f5eca5cbaa6792131600ca17",
    "m/44'/1'/2'/0/0": "04877a756d2b82ddff342fa327b065326001b204b2f86a24ac36638b51623301416076d2eb1a048c2efa3934d5673bdf3db8d0f1e8ade406c6a478f0910cdb8c4c"
}
"""

TEST_PUBKEYS_JSON_INVALID = """
{
    "path_1": "02877a756d2b82ddff342fa327b065326001b204b2f86a24ac36638b5162330141",
    "path_2": "11223344"
}
"""
