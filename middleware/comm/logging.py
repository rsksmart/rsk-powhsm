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

import logging
import logging.config


def configure_logging(config_path):
    try:
        logging.config.fileConfig(config_path)
        _getlogger().info("Loaded logging configuration from '%s'", config_path)
    except Exception as e:
        _load_default_configuration()
        _getlogger().info(
            "Loaded default logging configuration ('%s' invalid)", config_path
        )
        _getlogger().debug("While loading from '%s': %s", config_path, str(e))


def _load_default_configuration():
    logging.config.dictConfig(
        {
            "version": 1,
            "formatters": {"user": {"format": "[%(levelname)s:%(name)s] %(message)s"}},
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "level": "DEBUG",
                    "formatter": "user",
                    "stream": "ext://sys.stdout",
                }
            },
            "root": {"level": "NOTSET", "handlers": ["console"]},
        }
    )


def _getlogger():
    return logging.getLogger("logging")
