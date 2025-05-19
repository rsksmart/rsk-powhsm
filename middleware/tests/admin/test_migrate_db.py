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

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch, call
from admin.migrate_db import do_migrate_db
from admin.misc import AdminError


@patch("sys.stdout")
@patch("admin.migrate_db.do_unlock")
@patch("admin.migrate_db.get_hsm")
@patch("admin.migrate_db.get_sgx_hsm")
@patch("admin.migrate_db.dispose_hsm")
@patch("admin.migrate_db.SGXMigrationAuthorization")
class TestMigrateDb(TestCase):
    def setUp(self):
        options = SimpleNamespace()
        options.no_unlock = False
        options.verbose = "is-verbose"
        options.destination_sgx_host = "sgx-host"
        options.destination_sgx_port = 2345
        options.migration_authorization_file_path = "a-migauth-path"
        self.options = options

    def setupMocks(self, sgx_migration_authorization, dispose_hsm, get_sgx_hsm,
                   get_hsm, do_unlock):
        self.dispose_hsm = dispose_hsm
        self.get_sgx_hsm = get_sgx_hsm
        self.get_hsm = get_hsm
        self.do_unlock = do_unlock
        self.sgx_migration_authorization = sgx_migration_authorization

        self.src_hsm = Mock()
        self.dst_hsm = Mock()

        mig_spec = Mock()
        mig_spec.exporter = "aa"*32
        mig_spec.importer = "bb"*32
        self.sgx_migration_authorization_inst = Mock()
        self.sgx_migration_authorization_inst.migration_spec = mig_spec
        self.sgx_migration_authorization_inst.signatures = \
            ["7369672d6f6e65", "7369672d74776f", "7369672d7468726565"]
        self.sgx_migration_authorization.from_jsonfile.return_value = \
            self.sgx_migration_authorization_inst

        self.src_hsm.migrate_db_get_evidence.return_value = b"the source evidence"
        self.dst_hsm.migrate_db_get_evidence.return_value = b"the destination evidence"
        self.src_hsm.migrate_db_get_data.return_value = b"the source data"

        get_hsm.return_value = self.src_hsm
        get_sgx_hsm.return_value = self.dst_hsm

    def assert_disposed_hsms(self):
        self.assertEqual(2, self.dispose_hsm.call_count)
        self.assertEqual(call(self.src_hsm), self.dispose_hsm.call_args_list[0])
        self.assertEqual(call(self.dst_hsm), self.dispose_hsm.call_args_list[1])

    def test_ok(self, *args):
        self.setupMocks(*args[:-1])

        do_migrate_db(self.options)

        self.do_unlock.assert_called_with(self.options, label=False)
        self.get_hsm.assert_called_with("is-verbose")
        self.get_sgx_hsm.assert_called_with("sgx-host", 2345, "is-verbose")

        self.sgx_migration_authorization.from_jsonfile.assert_called_with(
            "a-migauth-path")

        self.src_hsm.migrate_db_spec.assert_called_with(
            0x01,
            bytes.fromhex("aa"*32),
            bytes.fromhex("bb"*32),
            [b"sig-one", b"sig-two", b"sig-three"])
        self.dst_hsm.migrate_db_spec.assert_called_with(
            0x02,
            bytes.fromhex("aa"*32),
            bytes.fromhex("bb"*32),
            [b"sig-one", b"sig-two", b"sig-three"])

        self.src_hsm.migrate_db_get_evidence.assert_called()
        self.dst_hsm.migrate_db_get_evidence.assert_called()

        self.src_hsm.migrate_db_send_evidence.assert_called_with(
            b"the destination evidence")
        self.dst_hsm.migrate_db_send_evidence.assert_called_with(
            b"the source evidence")

        self.src_hsm.migrate_db_get_data.assert_called()
        self.dst_hsm.migrate_db_send_data.assert_called_with(b"the source data")

        self.assert_disposed_hsms()

    def test_no_migauth(self, *args):
        self.setupMocks(*args[:-1])

        self.options.migration_authorization_file_path = None

        with self.assertRaises(AdminError) as e:
            do_migrate_db(self.options)

        self.assertIn("file path given", e.exception.args[0])

        self.sgx_migration_authorization.from_jsonfile.assert_not_called()
        self.do_unlock.assert_not_called()
        self.get_hsm.assert_not_called()
        self.get_sgx_hsm.assert_not_called()

    def test_migauth_load_fails(self, *args):
        self.setupMocks(*args[:-1])

        self.sgx_migration_authorization.from_jsonfile.side_effect = \
            Exception("json made a boo boo")

        with self.assertRaises(AdminError) as e:
            do_migrate_db(self.options)

        self.assertIn("json made a boo boo", e.exception.args[0])

        self.sgx_migration_authorization.from_jsonfile.assert_called_with(
            "a-migauth-path")
        self.do_unlock.assert_not_called()
        self.get_hsm.assert_not_called()
        self.get_sgx_hsm.assert_not_called()

    def test_migauth_no_sigs(self, *args):
        self.setupMocks(*args[:-1])

        self.sgx_migration_authorization_inst.signatures = []

        with self.assertRaises(AdminError) as e:
            do_migrate_db(self.options)

        self.assertIn("At least one signature", e.exception.args[0])

        self.sgx_migration_authorization.from_jsonfile.assert_called_with(
            "a-migauth-path")
        self.do_unlock.assert_not_called()
        self.get_hsm.assert_not_called()
        self.get_sgx_hsm.assert_not_called()

    def test_migauth_invalid_exporter(self, *args):
        self.setupMocks(*args[:-1])

        self.sgx_migration_authorization_inst.migration_spec.exporter = "not-hex"

        with self.assertRaises(AdminError) as e:
            do_migrate_db(self.options)

        self.assertIn("non-hexadecimal", e.exception.args[0])

        self.sgx_migration_authorization.from_jsonfile.assert_called_with(
            "a-migauth-path")
        self.do_unlock.assert_not_called()
        self.get_hsm.assert_not_called()
        self.get_sgx_hsm.assert_not_called()

    def test_migauth_invalid_importer(self, *args):
        self.setupMocks(*args[:-1])

        self.sgx_migration_authorization_inst.migration_spec.importer = "not-hex"

        with self.assertRaises(AdminError) as e:
            do_migrate_db(self.options)

        self.assertIn("non-hexadecimal", e.exception.args[0])

        self.sgx_migration_authorization.from_jsonfile.assert_called_with(
            "a-migauth-path")
        self.do_unlock.assert_not_called()
        self.get_hsm.assert_not_called()
        self.get_sgx_hsm.assert_not_called()

    def test_migauth_invalid_signature(self, *args):
        self.setupMocks(*args[:-1])

        self.sgx_migration_authorization_inst.signatures.append("not-hex")

        with self.assertRaises(AdminError) as e:
            do_migrate_db(self.options)

        self.assertIn("non-hexadecimal", e.exception.args[0])

        self.sgx_migration_authorization.from_jsonfile.assert_called_with(
            "a-migauth-path")
        self.do_unlock.assert_not_called()
        self.get_hsm.assert_not_called()
        self.get_sgx_hsm.assert_not_called()

    def test_unlock_fails(self, *args):
        self.setupMocks(*args[:-1])

        self.do_unlock.side_effect = RuntimeError("unlock boo boo")

        with self.assertRaises(AdminError) as e:
            do_migrate_db(self.options)

        self.assertIn("unlock device", e.exception.args[0])
        self.assertIn("boo boo", e.exception.args[0])

        self.sgx_migration_authorization.from_jsonfile.assert_called_with(
            "a-migauth-path")
        self.get_hsm.assert_not_called()
        self.get_sgx_hsm.assert_not_called()

    def test_spec_fails(self, *args):
        self.setupMocks(*args[:-1])

        self.dst_hsm.migrate_db_spec.side_effect = RuntimeError("wrong spec")

        with self.assertRaises(AdminError) as e:
            do_migrate_db(self.options)

        self.assertIn("Failed to migrate DB", e.exception.args[0])
        self.assertIn("wrong spec", e.exception.args[0])

        self.sgx_migration_authorization.from_jsonfile.assert_called_with(
            "a-migauth-path")
        self.do_unlock.assert_called_with(self.options, label=False)
        self.get_hsm.assert_called_with("is-verbose")
        self.get_sgx_hsm.assert_called_with("sgx-host", 2345, "is-verbose")

        self.src_hsm.migrate_db_spec.assert_called_with(
            0x01,
            bytes.fromhex("aa"*32),
            bytes.fromhex("bb"*32),
            [b"sig-one", b"sig-two", b"sig-three"])
        self.dst_hsm.migrate_db_spec.assert_called_with(
            0x02,
            bytes.fromhex("aa"*32),
            bytes.fromhex("bb"*32),
            [b"sig-one", b"sig-two", b"sig-three"])

        self.src_hsm.migrate_db_get_evidence.assert_not_called()
        self.dst_hsm.migrate_db_get_evidence.assert_not_called()
        self.src_hsm.migrate_db_send_evidence.assert_not_called()
        self.dst_hsm.migrate_db_send_evidence.assert_not_called()
        self.src_hsm.migrate_db_get_data.assert_not_called()
        self.dst_hsm.migrate_db_send_data.assert_not_called()

        self.assert_disposed_hsms()

    def test_get_evidence_fails(self, *args):
        self.setupMocks(*args[:-1])

        self.src_hsm.migrate_db_get_evidence.side_effect = \
            RuntimeError("evidence no no")

        with self.assertRaises(AdminError) as e:
            do_migrate_db(self.options)

        self.assertIn("Failed to migrate DB", e.exception.args[0])
        self.assertIn("evidence no no", e.exception.args[0])

        self.sgx_migration_authorization.from_jsonfile.assert_called_with(
            "a-migauth-path")
        self.do_unlock.assert_called_with(self.options, label=False)
        self.get_hsm.assert_called_with("is-verbose")
        self.get_sgx_hsm.assert_called_with("sgx-host", 2345, "is-verbose")

        self.src_hsm.migrate_db_spec.assert_called_with(
            0x01,
            bytes.fromhex("aa"*32),
            bytes.fromhex("bb"*32),
            [b"sig-one", b"sig-two", b"sig-three"])
        self.dst_hsm.migrate_db_spec.assert_called_with(
            0x02,
            bytes.fromhex("aa"*32),
            bytes.fromhex("bb"*32),
            [b"sig-one", b"sig-two", b"sig-three"])

        self.src_hsm.migrate_db_get_evidence.assert_called()
        self.dst_hsm.migrate_db_get_evidence.assert_not_called()
        self.src_hsm.migrate_db_send_evidence.assert_not_called()
        self.dst_hsm.migrate_db_send_evidence.assert_not_called()
        self.src_hsm.migrate_db_get_data.assert_not_called()
        self.dst_hsm.migrate_db_send_data.assert_not_called()

        self.assert_disposed_hsms()

    def test_send_evidence_fails(self, *args):
        self.setupMocks(*args[:-1])

        self.dst_hsm.migrate_db_send_evidence.side_effect = \
            RuntimeError("sending bad bad")

        with self.assertRaises(AdminError) as e:
            do_migrate_db(self.options)

        self.assertIn("Failed to migrate DB", e.exception.args[0])
        self.assertIn("sending bad bad", e.exception.args[0])

        self.sgx_migration_authorization.from_jsonfile.assert_called_with(
            "a-migauth-path")
        self.do_unlock.assert_called_with(self.options, label=False)
        self.get_hsm.assert_called_with("is-verbose")
        self.get_sgx_hsm.assert_called_with("sgx-host", 2345, "is-verbose")

        self.src_hsm.migrate_db_spec.assert_called_with(
            0x01,
            bytes.fromhex("aa"*32),
            bytes.fromhex("bb"*32),
            [b"sig-one", b"sig-two", b"sig-three"])
        self.dst_hsm.migrate_db_spec.assert_called_with(
            0x02,
            bytes.fromhex("aa"*32),
            bytes.fromhex("bb"*32),
            [b"sig-one", b"sig-two", b"sig-three"])

        self.src_hsm.migrate_db_get_evidence.assert_called()
        self.dst_hsm.migrate_db_get_evidence.assert_called()
        self.src_hsm.migrate_db_send_evidence.assert_called_with(
            b"the destination evidence")
        self.dst_hsm.migrate_db_send_evidence.assert_called_with(
            b"the source evidence")
        self.src_hsm.migrate_db_get_data.assert_not_called()
        self.dst_hsm.migrate_db_send_data.assert_not_called()

        self.assert_disposed_hsms()

    def test_get_data_fails(self, *args):
        self.setupMocks(*args[:-1])

        self.src_hsm.migrate_db_get_data.side_effect = RuntimeError("data nana")

        with self.assertRaises(AdminError) as e:
            do_migrate_db(self.options)

        self.assertIn("Failed to migrate DB", e.exception.args[0])
        self.assertIn("data nana", e.exception.args[0])

        self.sgx_migration_authorization.from_jsonfile.assert_called_with(
            "a-migauth-path")
        self.do_unlock.assert_called_with(self.options, label=False)
        self.get_hsm.assert_called_with("is-verbose")
        self.get_sgx_hsm.assert_called_with("sgx-host", 2345, "is-verbose")

        self.src_hsm.migrate_db_spec.assert_called_with(
            0x01,
            bytes.fromhex("aa"*32),
            bytes.fromhex("bb"*32),
            [b"sig-one", b"sig-two", b"sig-three"])
        self.dst_hsm.migrate_db_spec.assert_called_with(
            0x02,
            bytes.fromhex("aa"*32),
            bytes.fromhex("bb"*32),
            [b"sig-one", b"sig-two", b"sig-three"])

        self.src_hsm.migrate_db_get_evidence.assert_called()
        self.dst_hsm.migrate_db_get_evidence.assert_called()
        self.src_hsm.migrate_db_send_evidence.assert_called_with(
            b"the destination evidence")
        self.dst_hsm.migrate_db_send_evidence.assert_called_with(
            b"the source evidence")
        self.src_hsm.migrate_db_get_data.assert_called()
        self.dst_hsm.migrate_db_send_data.assert_not_called()

        self.assert_disposed_hsms()

    def test_send_data_fails(self, *args):
        self.setupMocks(*args[:-1])

        self.dst_hsm.migrate_db_send_data.side_effect = RuntimeError("import boo boo")

        with self.assertRaises(AdminError) as e:
            do_migrate_db(self.options)

        self.assertIn("Failed to migrate DB", e.exception.args[0])
        self.assertIn("import boo boo", e.exception.args[0])

        self.sgx_migration_authorization.from_jsonfile.assert_called_with(
            "a-migauth-path")
        self.do_unlock.assert_called_with(self.options, label=False)
        self.get_hsm.assert_called_with("is-verbose")
        self.get_sgx_hsm.assert_called_with("sgx-host", 2345, "is-verbose")

        self.src_hsm.migrate_db_spec.assert_called_with(
            0x01,
            bytes.fromhex("aa"*32),
            bytes.fromhex("bb"*32),
            [b"sig-one", b"sig-two", b"sig-three"])
        self.dst_hsm.migrate_db_spec.assert_called_with(
            0x02,
            bytes.fromhex("aa"*32),
            bytes.fromhex("bb"*32),
            [b"sig-one", b"sig-two", b"sig-three"])

        self.src_hsm.migrate_db_get_evidence.assert_called()
        self.dst_hsm.migrate_db_get_evidence.assert_called()
        self.src_hsm.migrate_db_send_evidence.assert_called_with(
            b"the destination evidence")
        self.dst_hsm.migrate_db_send_evidence.assert_called_with(
            b"the source evidence")
        self.src_hsm.migrate_db_get_data.assert_called()
        self.dst_hsm.migrate_db_send_data.assert_called_with(b"the source data")

        self.assert_disposed_hsms()
