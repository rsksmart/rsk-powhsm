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
import logging.handlers
import os
import shutil
import tempfile


# TimedRotatingFileHandler variant that gzip-compresses rotated log files
# on rollover.
class LogRotatingHandler(logging.handlers.TimedRotatingFileHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.namer = self._namer
        self.rotator = self._rotator

    @staticmethod
    def _namer(name):
        return name + ".gz"

    @staticmethod
    def _rotator(source, dest):
        # Compress into a sibling temp file, copy source's mode/mtime onto
        # it, then atomically move it into place. This guarantees that a
        # failure mid-compression cannot leave a partial .gz at `dest` or
        # destroy `source` before the compressed copy is durable.
        dest_dir = os.path.dirname(dest) or "."
        fd, tmp_path = tempfile.mkstemp(
            prefix=os.path.basename(dest) + ".",
            suffix=".tmp",
            dir=dest_dir,
        )
        os.close(fd)
        try:
            with open(source, "rb") as f_in, \
                    gzip.open(tmp_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            shutil.copystat(source, tmp_path)
            os.replace(tmp_path, dest)
        except BaseException:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise
        os.remove(source)
