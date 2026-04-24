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

import gzip
import logging
import os
import shutil
import tempfile
import time
from unittest import TestCase
from unittest.mock import patch

from comm.compressed_log_rotating_handler import CompressedLogRotatingHandler


class TestCompressedLogRotatingHandler(TestCase):

    def setUp(self):
        self._saved_disable_level = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.tmpdir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.tmpdir, "test.log")
        self.logger = logging.getLogger("test_compressed_log_rotating_handler")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        self.handler = CompressedLogRotatingHandler(
            self.log_path,
            when="midnight",
            interval=1,
            backupCount=5,
        )
        self.logger.addHandler(self.handler)

    def tearDown(self):
        self.logger.removeHandler(self.handler)
        self.handler.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        logging.disable(self._saved_disable_level)

    def test_ok(self):
        self.logger.info("hello")
        self.handler.flush()

        with open(self.log_path) as f:
            self.assertEqual("hello\n", f.read())

    def test_rollover_ok(self):
        self.logger.info("before")
        self.handler.flush()

        self.handler.doRollover()

        self.logger.info("after")
        self.handler.flush()

        # Post-rollover records keep flowing to the base filename
        with open(self.log_path) as f:
            self.assertEqual("after\n", f.read())

        # Exactly one dated .gz backup alongside the base file
        entries = sorted(os.listdir(self.tmpdir))
        self.assertEqual(2, len(entries))
        self.assertEqual("test.log", entries[0])
        self.assertRegex(entries[1], r"^test\.log\.\d{4}-\d{2}-\d{2}\.gz$")

        # Backup is valid gzip and holds the pre-rollover record
        with gzip.open(os.path.join(self.tmpdir, entries[1]), "rb") as f:
            self.assertEqual(b"before\n", f.read())

    def test_multiple_rollovers_respect_backup_count(self):
        # Rebuild the handler with a tight backupCount so pruning kicks
        # in within the scope of a single test.
        self.logger.removeHandler(self.handler)
        self.handler.close()
        self.handler = CompressedLogRotatingHandler(
            self.log_path,
            when="S",
            interval=1,
            backupCount=2,
        )
        self.logger.addHandler(self.handler)

        # Each rollover must produce a .gz with a distinct dated suffix;
        # otherwise the stdlib removes the existing dfn before rotation
        # and we would be exercising overwrites, not backupCount pruning.
        # The dated suffix is derived from (rolloverAt - interval), so
        # we force it forward one day per rollover.
        base = int(time.time())
        for i, record in enumerate(("first", "second", "third")):
            self.logger.info(record)
            self.handler.flush()
            self.handler.rolloverAt = base + self.handler.interval + i * 86400
            self.handler.doRollover()

        # Only the most recent backupCount backups survive; the oldest
        # one must have been pruned by getFilesToDelete().
        gz_entries = sorted(e for e in os.listdir(self.tmpdir) if e.endswith(".gz"))
        self.assertEqual(2, len(gz_entries))

        # The two survivors hold the two newest records in chronological
        # order, verifying that rollovers with our .gz namer neither
        # overwrite each other nor confuse getFilesToDelete().
        contents = []
        for name in gz_entries:
            with gzip.open(os.path.join(self.tmpdir, name), "rb") as f:
                contents.append(f.read())
        self.assertEqual([b"second\n", b"third\n"], contents)

    def test_rollover_failure_preserves_source_and_cleans_up(self):
        self.logger.info("before-failure")
        self.handler.flush()

        with patch(
            "comm.compressed_log_rotating_handler.shutil.copyfileobj",
            side_effect=OSError("disk full")
        ):
            with self.assertRaises(OSError):
                self.handler.doRollover()

        # Base log is intact and still holds the pre-rollover record
        with open(self.log_path) as f:
            self.assertEqual("before-failure\n", f.read())

        # No .gz backup was produced for this rollover
        gz_entries = [e for e in os.listdir(self.tmpdir) if e.endswith(".gz")]
        self.assertEqual([], gz_entries)

        # No leftover .tmp files from the compression attempt
        tmp_entries = [e for e in os.listdir(self.tmpdir) if e.endswith(".tmp")]
        self.assertEqual([], tmp_entries)
