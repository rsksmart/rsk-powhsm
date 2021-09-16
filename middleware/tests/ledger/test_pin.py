import string
from unittest import TestCase
from unittest.mock import MagicMock, call, patch
from parameterized import parameterized
import ledger.pin as pin


class TestBasePin(TestCase):
    def test_generate_pin(self):
        for i in range(1000):
            p = pin.BasePin.generate_pin()
            self.assertEqual(8, len(p))
            self.assertEqual(bytes, type(p))
            self.assertTrue(
                all(map(lambda c: chr(c) in string.ascii_letters + string.digits, p)))
            self.assertTrue(any(map(lambda c: chr(c) in string.ascii_letters, p)))

    @parameterized.expand([
        ("abc", False),
        ("abcd", False),
        ("abc1", False),
        ("abcde", False),
        ("abc12", False),
        ("abcdef", False),
        ("abc12f", False),
        ("abcdefg", False),
        ("ab2d68g", False),
        ("abcdefgh", True),
        ("8b23ef1s", True),
        ("abcdefghi", False),
        ("MNO", False),
        ("MNOP", False),
        ("MNO2", False),
        ("MNOPQ", False),
        ("MN3P4", False),
        ("MNOPQR", False),
        ("M1245R", False),
        ("MNOPQRS", False),
        ("M656QR3", False),
        ("MNOPQRST", True),
        ("MN22P3S9", True),
        ("MNOPQRSTU", False),
        ("1NO4Q6S8U", False),
        ("1234", False),
        ("123456", False),
        ("12345678", False),
        ("some-th", False),
        ("a1-@.;", False),
        ("!@#$%^&*", False),
        ("(),./;']", False),
    ])
    def test_is_valid(self, p, expected_validity):
        self.assertEqual(pin.BasePin.is_valid(p.encode()), expected_validity)

    @parameterized.expand([
        ("abc", False),
        ("abcd", False),
        ("abc1", False),
        ("abcde", False),
        ("abc12", False),
        ("abcdef", False),
        ("abc12f", False),
        ("abcdefg", False),
        ("ab2d68g", False),
        ("abcdefgh", True),
        ("8b23ef1s", True),
        ("abcdefghi", False),
        ("MNO", False),
        ("MNOP", False),
        ("MNO2", False),
        ("MNOPQ", False),
        ("MN3P4", False),
        ("MNOPQR", False),
        ("M1245R", False),
        ("MNOPQRS", False),
        ("M656QR3", False),
        ("MNOPQRST", True),
        ("MN22P3S9", True),
        ("MNOPQRSTU", False),
        ("1NO4Q6S8U", False),
        ("1234", False),
        ("123456", False),
        ("12345678", True),
        ("some-th", False),
        ("a1-@.;", False),
        ("!@#$%^&*", False),
        ("(),./;']", False),
    ])
    def test_is_valid_not_require_alpha(self, p, expected_validity):
        self.assertEqual(pin.BasePin.is_valid(p.encode(), require_alpha=False),
                         expected_validity)


class TestFileBasedPin(TestCase):
    @patch("ledger.pin.open")
    def test_new(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value = mock_file
        p = pin.FileBasedPin.new("a-path")
        self.assertTrue(pin.BasePin.is_valid(p))
        self.assertEqual([call("a-path", "wb")], mock_open.call_args_list)
        self.assertEqual([call(p)], mock_file.__enter__().write.call_args_list)
        self.assertTrue(mock_file.__exit__.called)

    @patch("os.path.isfile")
    @patch("ledger.pin.open")
    def test_init_pin_doesnotexist(self, mock_open, mock_isfile):
        mock_isfile.return_value = False
        p = pin.FileBasedPin("a-path", b"abcdefgh")
        self.assertEqual([call("a-path")], mock_isfile.call_args_list)
        self.assertFalse(mock_open.called)
        self.assertEqual(b"abcdefgh", p.get_pin())
        self.assertTrue(p.needs_change())

    @patch("os.path.isfile")
    @patch("ledger.pin.open")
    def test_init_pin_exists(self, mock_open, mock_isfile):
        mock_isfile.return_value = True
        mock_file = MagicMock()
        mock_file.__enter__().read.return_value = b"othpinab\n"
        mock_open.return_value = mock_file
        p = pin.FileBasedPin("a-path", b"abcdefgh")
        self.assertEqual([call("a-path")], mock_isfile.call_args_list)
        self.assertEqual([call("a-path", "rb")], mock_open.call_args_list)
        self.assertEqual(b"othpinab", p.get_pin())
        self.assertFalse(p.needs_change())

    @patch("os.path.isfile")
    @patch("ledger.pin.open")
    def test_pin_change(self, mock_open, mock_isfile):
        mock_isfile.return_value = False
        mock_file = MagicMock()
        mock_open.return_value = mock_file
        p = pin.FileBasedPin("a-path", b"abcdefgh")
        self.assertEqual(b"abcdefgh", p.get_pin())
        self.assertEqual(None, p.get_new_pin())
        self.assertTrue(p.needs_change())
        p.start_change()
        np = p.get_new_pin()
        self.assertEqual(b"abcdefgh", p.get_pin())
        self.assertNotEqual(None, np)
        self.assertTrue(pin.BasePin.is_valid(np))
        p.commit_change()
        self.assertEqual(np, p.get_pin())
        self.assertEqual(None, p.get_new_pin())
        self.assertFalse(p.needs_change())
        self.assertEqual([call("a-path", "wb")], mock_open.call_args_list)
        self.assertEqual([call(np)], mock_file.__enter__().write.call_args_list)
        self.assertTrue(mock_file.__exit__.called)

    @patch("os.path.isfile")
    @patch("ledger.pin.open")
    def test_pin_change_aborted(self, mock_open, mock_isfile):
        mock_isfile.return_value = False
        p = pin.FileBasedPin("a-path", b"abcdefgh")
        self.assertEqual(b"abcdefgh", p.get_pin())
        self.assertEqual(None, p.get_new_pin())
        self.assertTrue(p.needs_change())
        p.start_change()
        np = p.get_new_pin()
        self.assertEqual(b"abcdefgh", p.get_pin())
        self.assertNotEqual(None, np)
        self.assertTrue(pin.BasePin.is_valid(np))
        p.abort_change()
        self.assertEqual(b"abcdefgh", p.get_pin())
        self.assertEqual(None, p.get_new_pin())
        self.assertTrue(p.needs_change())
        self.assertFalse(mock_open.called)
