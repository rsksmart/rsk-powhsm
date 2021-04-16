import os,random,string
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
    def is_valid(cls, pin, require_alpha=True):
        if type(pin) != bytes:
            return False

        if len(pin) != cls.PIN_LENGTH:
            return False

        if not all(map(lambda c: chr(c) in cls.POSSIBLE_CHARS, pin)):
            return False

        if not require_alpha:
            return True

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
