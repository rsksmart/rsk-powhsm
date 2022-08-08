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

import os
import random
import string
import logging


class PinError(RuntimeError):
    pass


class BasePin:
    PIN_LENGTH = 8
    POSSIBLE_CHARS = string.ascii_letters + string.digits
    ALPHA_CHARS = string.ascii_letters

    @classmethod
    def generate_pin(cls):
        random.seed()
        pin = None
        while pin is None or not cls.is_valid(pin.encode()):
            pin = ""
            for i in range(cls.PIN_LENGTH):
                pin += random.choice(cls.POSSIBLE_CHARS)
        return pin.encode()

    @classmethod
    def is_valid(cls, pin, any_pin=False):
        if type(pin) != bytes:
            return False

        if not all(map(lambda c: chr(c) in cls.POSSIBLE_CHARS, pin)):
            return False

        if any_pin:
            return True

        if len(pin) != cls.PIN_LENGTH:
            return False

        return any(map(lambda c: chr(c) in cls.ALPHA_CHARS, pin))


# Handles PIN initialization and loading
class FileBasedPin(BasePin):
    @classmethod
    def new(cls, path):
        # Generate a new random pin and save to the given path. Return the
        # generated pin
        with open(path, 'wb') as file:
            pin = cls.generate_pin()
            file.write(pin)
        return pin

    def __init__(self, path, default_pin, force_change=False):
        self.logger = logging.getLogger("pin")
        self._path = path

        # Check pin file existence
        try:
            self.logger.info("Checking whether pin file '%s' exists", path)
            pin_file_exists = os.path.isfile(path)
        except Exception as e:
            self._error("Error checking file existence: %s" % format(e))

        # Load pin
        if pin_file_exists:
            try:
                self.logger.info("Loading PIN from '%s'", path)
                with open(path, 'rb') as file:
                    self._pin = file.read().strip()
            except Exception as e:
                self._error("Error loading pin: %s" % format(e))
        else:
            self.logger.info("Using default PIN")
            self._pin = default_pin

        # Make sure pin is valid
        if not self.is_valid(self._pin):
            self._error("Invalid pin: %s" % self._pin)

        # Pin needs to be changed if no pin file found or a pin change is forced
        self._needs_change = force_change or not pin_file_exists
        self._changing = False

    # Returns the current pin
    def get_pin(self):
        return self._pin

    def get_new_pin(self):
        if not self._changing:
            return None

        return self._new_pin

    # Indicates whether the current pin needs changing
    def needs_change(self):
        return self._needs_change

    # Starts a pin change and generates a new pin
    def start_change(self):
        self.logger.info("Starting PIN change")

        if self._changing or not self._needs_change:
            return

        self._changing = True
        self._new_pin = self.generate_pin()

        self.logger.info("New PIN generated")

    # Finalizes a pin change by commiting the changes to disk
    def commit_change(self):
        self.logger.info("Commiting PIN change to disk")
        if not self._changing:
            return

        try:
            with open(self._path, "wb") as file:
                file.write(self._new_pin)
        except Exception as e:
            self._error("Error commiting: %s" % format(e))

        self._pin = self._new_pin
        self._new_pin = None
        self._changing = False
        self._needs_change = False

        self.logger.info("PIN change committed to disk")

    # Aborts a pin change
    def abort_change(self):
        self.logger.info("Aborting PIN change")

        if not self._changing:
            return

        self._new_pin = None
        self._changing = False

        self.logger.info("PIN change aborted")

    def _error(self, msg):
        self.logger.error(msg)
        raise PinError(msg)
