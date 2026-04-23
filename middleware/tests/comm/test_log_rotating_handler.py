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
from unittest import TestCase
from unittest.mock import patch

from comm.log_rotating_handler import LogRotatingHandler


class TestLogRotatingHandler(TestCase):

    def setUp(self):
        logging.disable(logging.NOTSET)
        self.tmpdir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.tmpdir, "test.log")
        self.logger = logging.getLogger("test_log_rotating_handler")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        self.handler = LogRotatingHandler(
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
        logging.disable(logging.CRITICAL)

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

    def test_rollover_failure_preserves_source_and_cleans_up(self):
        self.logger.info("before-failure")
        self.handler.flush()

        with patch(
                "comm.log_rotating_handler.shutil.copyfileobj",
                side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.handler.doRollover()

        # Base log is intact and still holds the pre-rollover record
        with open(self.log_path) as f:
            self.assertEqual("before-failure\n", f.read())

        # No .gz backup was produced for this rollover
        gz_entries = [e for e in os.listdir(self.tmpdir)
                      if e.endswith(".gz")]
        self.assertEqual([], gz_entries)

        # No leftover .tmp files from the compression attempt
        tmp_entries = [e for e in os.listdir(self.tmpdir)
                       if e.endswith(".tmp")]
        self.assertEqual([], tmp_entries)
