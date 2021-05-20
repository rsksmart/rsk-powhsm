from unittest import TestCase
from unittest.mock import Mock, patch, call
from parameterized import parameterized
from tests.utils import list_product
from ledger.hsm2dongle import HSM2Dongle, HSM2DongleError, HSM2DongleTimeout, HSM2DongleErrorResult
from ledger.version import HSM2FirmwareVersion
from ledgerblue.commException import CommException

import logging
logging.disable(logging.CRITICAL)

class _TestHSM2DongleBase(TestCase):
    DONGLE_EXCHANGE_TIMEOUT = 10

    @patch("ledger.hsm2dongle.getDongle")
    def setUp(self, getDongleMock):
        self.dongle = Mock()
        self.getDongleMock = getDongleMock
        self.getDongleMock.return_value = self.dongle
        self.hsm2dongle = HSM2Dongle("a-debug-value")
        self.hsm2dongle.connect()

    def spec_to_exchange(self, spec, trim=False):
        trim_length = spec[0][-1] if trim else 0
        block_size = len(spec[0])-trim_length
        chunk_size = spec[1]
        exchanges = [bytes([0, 0, 0x04, chunk_size])]*(block_size//chunk_size)
        remaining = block_size - len(exchanges)*chunk_size
        exchanges = [bytes([0, 0, 0x03])] + exchanges + [bytes([0, 0, 0x04, remaining])]
        return exchanges

    def assert_exchange(self, payloads, timeouts=None):
        if timeouts is None:
            timeouts = [None]*len(payloads)
        calls = list(map(lambda z: call(bytes([0x80]) + bytes(z[0]), \
                                        timeout=(z[1] if z[1] is not None else self.DONGLE_EXCHANGE_TIMEOUT)), \
                         zip(payloads, timeouts)))

        self.assertEqual(len(payloads), len(self.dongle.exchange.call_args_list), msg="# of exchanges mismatch")

        for i, c in enumerate(calls):
            self.assertEqual(c, self.dongle.exchange.call_args_list[i], msg="%dth exchange failed" % (i+1))

class TestHSM2Dongle(_TestHSM2DongleBase):
    def test_connects_ok(self):
        self.assertEqual([call("a-debug-value")], self.getDongleMock.call_args_list)

    @patch("ledger.hsm2dongle.getDongle")
    def test_connects_error_comm(self, getDongleMock):
        getDongleMock.side_effect = CommException("a-message")
        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.connect()

    @patch("ledger.hsm2dongle.getDongle")
    def test_connects_error_other(self, getDongleMock):
        getDongleMock.side_effect = ValueError()
        with self.assertRaises(ValueError):
            self.hsm2dongle.connect()

    def test_get_current_mode(self):
        self.dongle.exchange.return_value = bytes([10, 2, 30])
        mode = self.hsm2dongle.get_current_mode()
        self.assertEqual(2, mode)
        self.assertEqual(self.hsm2dongle.MODE, type(mode))
        self.assert_exchange([[0x43]])

    def test_echo(self):
        self.dongle.exchange.return_value = bytes([0x80, 0x02, 0x41, 0x42, 0x43])
        self.assertTrue(self.hsm2dongle.echo())
        self.assert_exchange([[0x02, 0x41, 0x42, 0x43]])

    def test_echo_error(self):
        self.dongle.exchange.return_value = bytes([1, 2, 3])
        self.assertFalse(self.hsm2dongle.echo())
        self.assert_exchange([[0x02, 0x41, 0x42, 0x43]])

    def test_is_onboarded_yes(self):
        self.dongle.exchange.return_value = bytes([0, 1, 0])
        self.assertTrue(self.hsm2dongle.is_onboarded())
        self.assert_exchange([[0x06]])

    def test_is_onboarded_no(self):
        self.dongle.exchange.return_value = bytes([0, 0, 0])
        self.assertFalse(self.hsm2dongle.is_onboarded())
        self.assert_exchange([[0x06]])

    def test_onboard_ok(self):
        self.dongle.exchange.side_effect = [bytes([0])]*(32 + 5) + [bytes([0, 2, 0])]

        self.assertTrue(self.hsm2dongle.onboard(bytes(map(lambda i: i*2, range(32))), b"1234"))
        
        seed_exchanges = list(map(lambda i: [0x44, i, i*2], range(32)))
        pin_exchanges = [[0x41, 0, 4]] + list(map(lambda i: [0x41, i+1, ord(str(i+1))], range(4)))
        exchanges = seed_exchanges + pin_exchanges + [[0x07]]
        timeouts = [None]*len(exchanges)
        timeouts[-1] = HSM2Dongle.ONBOARDING.TIMEOUT
        self.assert_exchange(exchanges, timeouts)

    def test_onboard_wipe_error(self):
        self.dongle.exchange.side_effect = [bytes([0])]*(32 + 5) + [bytes([0, 1, 0])]

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.onboard(bytes(map(lambda i: i*2, range(32))), b"1234")

        seed_exchanges = list(map(lambda i: [0x44, i, i*2], range(32)))
        pin_exchanges = [[0x41, 0, 4]] + list(map(lambda i: [0x41, i+1, ord(str(i+1))], range(4)))
        exchanges = seed_exchanges + pin_exchanges + [[0x07]]
        timeouts = [None]*len(exchanges)
        timeouts[-1] = HSM2Dongle.ONBOARDING.TIMEOUT
        self.assert_exchange(exchanges, timeouts)

    def test_onboard_pin_error(self):
        self.dongle.exchange.side_effect = [bytes([0])]*(32 + 3) + [CommException("an-error")]

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.onboard(bytes(map(lambda i: i*2, range(32))), b"1234")

        seed_exchanges = list(map(lambda i: [0x44, i, i*2], range(32)))
        pin_exchanges = [[0x41, 0, 4]] + list(map(lambda i: [0x41, i+1, ord(str(i+1))], range(3)))
        exchanges = seed_exchanges + pin_exchanges
        self.assert_exchange(exchanges)

    def test_onboard_seed_error(self):
        self.dongle.exchange.side_effect = [bytes([0])]*30 + [CommException("an-error")]

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.onboard(bytes(map(lambda i: i*2, range(32))), b"1234")

        seed_exchanges = list(map(lambda i: [0x44, i, i*2], range(31)))
        self.assert_exchange(seed_exchanges)

    def test_unlock_ok(self):
        self.dongle.exchange.side_effect = [bytes([0]), bytes([1]), bytes([2]), bytes([0, 0, 1])]
        self.assertTrue(self.hsm2dongle.unlock(bytes([1,2,3])))
        self.assert_exchange([[0x41, 0, 1], [0x41, 1, 2], [0x41, 2, 3], [0xfe, 0x00, 0x00]])

    def test_unlock_pinerror(self):
        self.dongle.exchange.side_effect = [bytes([0]), bytes([1]), bytes([2]), bytes([0, 0, 0])]
        self.assertFalse(self.hsm2dongle.unlock(bytes([1,2,3])))
        self.assert_exchange([[0x41, 0, 1], [0x41, 1, 2], [0x41, 2, 3], [0xfe, 0x00, 0x00]])

    def test_new_pin(self):
        self.dongle.exchange.side_effect = [bytes([0]), bytes([1]), bytes([2]), bytes([3]), bytes([4])]
        self.hsm2dongle.new_pin(bytes([4,5,6]))
        self.assert_exchange([[0x41, 0, 3], [0x41, 1, 4], [0x41, 2, 5], [0x41, 3, 6], [0x08]])

    def test_version(self):
        self.dongle.exchange.return_value = bytes([0, 0, 6, 7, 8])
        version = self.hsm2dongle.get_version()
        self.assertEqual(HSM2FirmwareVersion, type(version))
        self.assertEqual(6, version.major)
        self.assertEqual(7, version.minor)
        self.assertEqual(8, version.patch)
        self.assert_exchange([[0x06]])

    def test_retries(self):
        self.dongle.exchange.return_value = bytes([0, 0, 57])
        retries = self.hsm2dongle.get_retries()
        self.assertEqual(57, retries)
        self.assert_exchange([[0x45]])

    def test_exit_menu(self):
        self.dongle.exchange.return_value = bytes([0])
        self.hsm2dongle.exit_menu()
        self.assert_exchange([[0xff, 0x00, 0x00]])

    def test_exit_menu_explicit_autoexec(self):
        self.dongle.exchange.return_value = bytes([0])
        self.hsm2dongle.exit_menu(autoexec=True)
        self.assert_exchange([[0xff, 0x00, 0x00]])

    def test_exit_menu_no_autoexec(self):
        self.dongle.exchange.return_value = bytes([0])
        self.hsm2dongle.exit_menu(autoexec=False)
        self.assert_exchange([[0xfa, 0x00, 0x00]])

    def test_get_public_key_ok(self):
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.dongle.exchange.return_value = bytes.fromhex("aabbccddee")
        self.assertEqual("aabbccddee", self.hsm2dongle.get_public_key(key_id))
        self.assert_exchange([[0x04, 0x11, 0x22, 0x33, 0x44]])

    def test_get_public_key_invalid_keyid(self):
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.dongle.exchange.side_effect = CommException("some message", 0x6a87)
        with self.assertRaises(HSM2DongleErrorResult):
            self.hsm2dongle.get_public_key(key_id)
        self.assert_exchange([[0x04, 0x11, 0x22, 0x33, 0x44]])

    def test_get_public_key_timeout(self):
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.dongle.exchange.side_effect = CommException("Timeout")
        with self.assertRaises(HSM2DongleTimeout):
            self.hsm2dongle.get_public_key(key_id)
        self.assert_exchange([[0x04, 0x11, 0x22, 0x33, 0x44]])

    def test_get_public_key_other_error(self):
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.dongle.exchange.side_effect = CommException("some other message", 0xffff)
        with self.assertRaises(HSM2DongleError):
            self.assertEqual("aabbccddee", self.hsm2dongle.get_public_key(key_id))
        self.assert_exchange([[0x04, 0x11, 0x22, 0x33, 0x44]])

    @patch("ledger.hsm2dongle.HSM2DongleSignature")
    def test_sign_authorized_ok(self, HSM2DongleSignatureMock):
        HSM2DongleSignatureMock.return_value = "the-signature"
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x02, 0x09]), # Response to key id, request 9 bytes of BTC tx
            bytes([0, 0, 0x02, 0x03]), # Response to first chunk of BTC tx, request additional 4 bytes
            bytes([0, 0, 0x04, 0x04]), # Response to second chunk of BTC tx, request first 4 bytes of receipt
            bytes([0, 0, 0x04, 0x06]), # Response to first chunk of receipt, request additional 6 bytes
            bytes([0, 0, 0x08, 0x04]), # Response to second chunk of receipt, request first 4 bytes of MP
            bytes([0, 0, 0x08, 0x03]), # Response to first chunk of MP, request additional 3 bytes
            bytes([0, 0, 0x08, 0x07]), # Response to second chunk of MP, request additional 7 bytes
            bytes([0, 0, 0x81, 0xaa, 0xbb, 0xcc, 0xdd]), # Response to second third of MP, sucess and signature
        ]
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.assertEqual((True, "the-signature"), \
                         self.hsm2dongle.sign_authorized(key_id=key_id,\
                                rsk_tx_receipt="00112233445566778899",\
                                receipt_merkle_proof=["334455", "6677", "aabbccddee"],\
                                btc_tx="aabbccddeeff7788",\
                                input_index=1234))

        self.assert_exchange([\
              [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xd2, 0x04, 0x00, 0x00], # Path and input index
              [0x02, 0x02, 0x0c, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee], # Length of payload plus first chunk of BTC tx
              [0x02, 0x02, 0xff, 0x77, 0x88], # Second chunk of BTC tx
              [0x02, 0x04, 0x00, 0x11, 0x22, 0x33], # First chunk of receipt
              [0x02, 0x04, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99], # Second chunk of receipt
              [0x02, 0x08, 0x03, 0x03, 0x33, 0x44], # First chunk of MP
              [0x02, 0x08, 0x55, 0x02, 0x66], # Second chunk of MP
              [0x02, 0x08, 0x77, 0x05, 0xaa, 0xbb, 0xcc, 0xdd, 0xee], # Third chunk of MP
        ])
        self.assertEqual([call(bytes([0xaa, 0xbb, 0xcc, 0xdd]))], HSM2DongleSignatureMock.call_args_list)

    @parameterized.expand([
        ("data_size", 0x6a87, -4),
        ("state", 0x6a89, -4),
        ("node_version", 0x6a92, -4),
        ("shared_prefix_too_big", 0x6a93, -4),
        ("receipt_hash_mismatch", 0x6a94, -4),
        ("node_chaining_mismatch", 0x6a95, -4),
        ("receipt_root_mismatch", 0x6a96, -4),
        ("unknown", 0x6aff, -10),
        ("unexpected", [0, 0, 0xff], -10),
    ])
    def test_sign_authorized_mp_invalid(self, _, device_error, expected_response):
        if type(device_error) == int:
            last_exchange = CommException("msg", device_error)
        else:
            last_exchange = bytes(device_error)
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x02, 0x09]), # Response to key id, request 9 bytes of BTC tx
            bytes([0, 0, 0x02, 0x03]), # Response to first chunk of BTC tx, request additional 4 bytes
            bytes([0, 0, 0x04, 0x04]), # Response to second chunk of BTC tx, request first 4 bytes of receipt
            bytes([0, 0, 0x04, 0x06]), # Response to first chunk of receipt, request additional 6 bytes
            bytes([0, 0, 0x08, 0x04]), # Response to second chunk of receipt, request first 4 bytes of MP
            bytes([0, 0, 0x08, 0x03]), # Response to first chunk of MP, request additional 3 bytes
            last_exchange, # Response to second chunk of MP, request additional 7 bytes
        ]
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.assertEqual((False, expected_response), \
                         self.hsm2dongle.sign_authorized(key_id=key_id,\
                                rsk_tx_receipt="00112233445566778899",\
                                receipt_merkle_proof=["334455", "6677", "aabbccddee"],\
                                btc_tx="aabbccddeeff7788",\
                                input_index=1234))

        self.assert_exchange([\
              [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xd2, 0x04, 0x00, 0x00], # Path and input index
              [0x02, 0x02, 0x0c, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee], # Length of payload plus first chunk of BTC tx
              [0x02, 0x02, 0xff, 0x77, 0x88], # Second chunk of BTC tx
              [0x02, 0x04, 0x00, 0x11, 0x22, 0x33], # First chunk of receipt
              [0x02, 0x04, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99], # Second chunk of receipt
              [0x02, 0x08, 0x03, 0x03, 0x33, 0x44], # First chunk of MP
              [0x02, 0x08, 0x55, 0x02, 0x66], # Second chunk of MP
        ])

    @parameterized.expand([
        ("too_many_nodes", ["aa"]*256),
        ("node_too_big", ["aa"]*100 + ["bb"*256]),
    ])
    def test_sign_authorized_mp_too_big(self, _, receipt_merkle_proof):
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x02, 0x09]), # Response to key id, request 9 bytes of BTC tx
            bytes([0, 0, 0x02, 0x03]), # Response to first chunk of BTC tx, request additional 4 bytes
            bytes([0, 0, 0x04, 0x04]), # Response to second chunk of BTC tx, request first 4 bytes of receipt
            bytes([0, 0, 0x04, 0x06]), # Response to first chunk of receipt, request additional 6 bytes
            bytes([0, 0, 0x08, 0x04]), # Response to second chunk of receipt, request first 4 bytes of MP
        ]
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.assertEqual((False, -4), \
                         self.hsm2dongle.sign_authorized(key_id=key_id,\
                                rsk_tx_receipt="00112233445566778899",\
                                receipt_merkle_proof=receipt_merkle_proof,\
                                btc_tx="aabbccddeeff7788",\
                                input_index=1234))

        self.assert_exchange([\
              [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xd2, 0x04, 0x00, 0x00], # Path and input index
              [0x02, 0x02, 0x0c, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee], # Length of payload plus first chunk of BTC tx
              [0x02, 0x02, 0xff, 0x77, 0x88], # Second chunk of BTC tx
              [0x02, 0x04, 0x00, 0x11, 0x22, 0x33], # First chunk of receipt
              [0x02, 0x04, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99], # Second chunk of receipt
        ])

    def test_sign_authorized_mp_unexpected_exc(self):
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x02, 0x09]), # Response to key id, request 9 bytes of BTC tx
            bytes([0, 0, 0x02, 0x03]), # Response to first chunk of BTC tx, request additional 4 bytes
            bytes([0, 0, 0x04, 0x04]), # Response to second chunk of BTC tx, request first 4 bytes of receipt
            bytes([0, 0, 0x04, 0x06]), # Response to first chunk of receipt, request additional 6 bytes
            bytes([0, 0, 0x08, 0x04]), # Response to second chunk of receipt, request first 4 bytes of MP
            bytes([0, 0, 0x08, 0x03]), # Response to first chunk of MP, request additional 3 bytes
            CommException("msg", 0xffff), # Response to second chunk of MP, request additional 7 bytes
        ]
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.sign_authorized(key_id=key_id,\
                rsk_tx_receipt="00112233445566778899",\
                receipt_merkle_proof=["334455", "6677", "aabbccddee"],\
                btc_tx="aabbccddeeff7788",\
                input_index=1234)

        self.assert_exchange([\
              [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xd2, 0x04, 0x00, 0x00], # Path and input index
              [0x02, 0x02, 0x0c, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee], # Length of payload plus first chunk of BTC tx
              [0x02, 0x02, 0xff, 0x77, 0x88], # Second chunk of BTC tx
              [0x02, 0x04, 0x00, 0x11, 0x22, 0x33], # First chunk of receipt
              [0x02, 0x04, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99], # Second chunk of receipt
              [0x02, 0x08, 0x03, 0x03, 0x33, 0x44], # First chunk of MP
              [0x02, 0x08, 0x55, 0x02, 0x66], # Second chunk of MP
        ])

    def test_sign_authorized_mp_invalid_format(self):
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x02, 0x09]), # Response to key id, request 9 bytes of BTC tx
            bytes([0, 0, 0x02, 0x03]), # Response to first chunk of BTC tx, request additional 4 bytes
            bytes([0, 0, 0x04, 0x04]), # Response to second chunk of BTC tx, request first 4 bytes of receipt
            bytes([0, 0, 0x04, 0x06]), # Response to first chunk of receipt, request additional 6 bytes
            bytes([0, 0, 0x08, 0x04]), # Response to second chunk of receipt, request first 4 bytes of MP
        ]
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.assertEqual((False, -4), \
                         self.hsm2dongle.sign_authorized(key_id=key_id,\
                                rsk_tx_receipt="00112233445566778899",\
                                receipt_merkle_proof=["334455", "6677", "not-a-hex"],\
                                btc_tx="aabbccddeeff7788",\
                                input_index=1234))

        self.assert_exchange([\
              [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xd2, 0x04, 0x00, 0x00], # Path and input index
              [0x02, 0x02, 0x0c, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee], # Length of payload plus first chunk of BTC tx
              [0x02, 0x02, 0xff, 0x77, 0x88], # Second chunk of BTC tx
              [0x02, 0x04, 0x00, 0x11, 0x22, 0x33], # First chunk of receipt
              [0x02, 0x04, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99], # Second chunk of receipt
        ])

    @parameterized.expand([
        ("data_size", 0x6a87, -3),
        ("state", 0x6a89, -3),
        ("rlp", 0x6a8a, -3),
        ("rlp_int", 0x6a8b, -3),
        ("rlp_depth", 0x6a8c, -3),
        ("unknown", 0x6aff, -10),
        ("unexpected", [0, 0, 0xff], -10),
    ])
    def test_sign_authorized_receipt_invalid(self, _, device_error, expected_response):
        if type(device_error) == int:
            last_exchange = CommException("msg", device_error)
        else:
            last_exchange = bytes(device_error)
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x02, 0x09]), # Response to key id, request 9 bytes of BTC tx
            bytes([0, 0, 0x02, 0x03]), # Response to first chunk of BTC tx, request additional 4 bytes
            bytes([0, 0, 0x04, 0x04]), # Response to second chunk of BTC tx, request first 4 bytes of receipt
            bytes([0, 0, 0x04, 0x06]), # Response to first chunk of receipt, request additional 6 bytes
            last_exchange, # Response to second chunk of receipt, specific error
        ]
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.assertEqual((False, expected_response), \
                         self.hsm2dongle.sign_authorized(key_id=key_id,\
                                rsk_tx_receipt="00112233445566778899",\
                                receipt_merkle_proof=["334455", "6677", "aabbccddee"],\
                                btc_tx="aabbccddeeff7788",\
                                input_index=1234))

        self.assert_exchange([\
              [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xd2, 0x04, 0x00, 0x00], # Path and input index
              [0x02, 0x02, 0x0c, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee], # Length of payload plus first chunk of BTC tx
              [0x02, 0x02, 0xff, 0x77, 0x88], # Second chunk of BTC tx
              [0x02, 0x04, 0x00, 0x11, 0x22, 0x33], # First chunk of receipt
              [0x02, 0x04, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99], # Second chunk of receipt
        ])

    def test_sign_authorized_receipt_unexpected_error_exc(self):
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x02, 0x09]), # Response to key id, request 9 bytes of BTC tx
            bytes([0, 0, 0x02, 0x03]), # Response to first chunk of BTC tx, request additional 4 bytes
            bytes([0, 0, 0x04, 0x04]), # Response to second chunk of BTC tx, request first 4 bytes of receipt
            bytes([0, 0, 0x04, 0x06]), # Response to first chunk of receipt, request additional 6 bytes
            CommException("", 0xffff), # Response to second chunk of receipt, unexpected exception
        ]
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.sign_authorized(key_id=key_id,\
                rsk_tx_receipt="00112233445566778899",\
                receipt_merkle_proof=["334455", "6677", "aabbccddee"],\
                btc_tx="aabbccddeeff7788",\
                input_index=1234)

        self.assert_exchange([\
              [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xd2, 0x04, 0x00, 0x00], # Path and input index
              [0x02, 0x02, 0x0c, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee], # Length of payload plus first chunk of BTC tx
              [0x02, 0x02, 0xff, 0x77, 0x88], # Second chunk of BTC tx
              [0x02, 0x04, 0x00, 0x11, 0x22, 0x33], # First chunk of receipt
              [0x02, 0x04, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99], # Second chunk of receipt
        ])

    @parameterized.expand([
        ("input", 0x6a88, -2),
        ("tx_hash_mismatch", 0x6a8d, -2),
        ("tx_version", 0x6a8e, -2),
        ("unknown", 0x6aff, -10),
        ("unexpected", [0, 0, 0xff], -10),
    ])
    def test_sign_authorized_btctx_invalid(self, _, device_error, expected_response):
        if type(device_error) == int:
            last_exchange = CommException("msg", device_error)
        else:
            last_exchange = bytes(device_error)
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x02, 0x09]), # Response to key id, request 9 bytes of BTC tx
            bytes([0, 0, 0x02, 0x03]), # Response to first chunk of BTC tx, request additional 4 bytes
            last_exchange, # Response to second chunk of BTC tx, specific error
        ]
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.assertEqual((False, expected_response), \
                         self.hsm2dongle.sign_authorized(key_id=key_id,\
                                rsk_tx_receipt="00112233445566778899",\
                                receipt_merkle_proof=["334455", "6677", "aabbccddee"],\
                                btc_tx="aabbccddeeff7788",\
                                input_index=1234))

        self.assert_exchange([\
              [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xd2, 0x04, 0x00, 0x00], # Path and input index
              [0x02, 0x02, 0x0c, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee], # Length of payload plus first chunk of BTC tx
              [0x02, 0x02, 0xff, 0x77, 0x88], # Second chunk of BTC tx
        ])

    def test_sign_authorized_btctx_unexpected_error_exc(self):
        for error_code in [0x6a88, 0x6a8d, 0x6a8e]:
            self.dongle.exchange.reset_mock()
            self.dongle.exchange.side_effect = [
                bytes([0, 0, 0x02, 0x09]), # Response to key id, request 9 bytes of BTC tx
                bytes([0, 0, 0x02, 0x03]), # Response to first chunk of BTC tx, request additional 4 bytes
                CommException("", 0xff), # Response to second chunk of BTC tx, exception
            ]
            key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
            with self.assertRaises(HSM2DongleError):
                self.hsm2dongle.sign_authorized(key_id=key_id,\
                    rsk_tx_receipt="00112233445566778899",\
                    receipt_merkle_proof=["334455", "6677", "aabbccddee"],\
                    btc_tx="aabbccddeeff7788",\
                    input_index=1234)

            self.assert_exchange([\
                  [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xd2, 0x04, 0x00, 0x00], # Path and input index
                  [0x02, 0x02, 0x0c, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee], # Length of payload plus first chunk of BTC tx
                  [0x02, 0x02, 0xff, 0x77, 0x88], # Second chunk of BTC tx
            ])

    @parameterized.expand([
        ("data_size", 0x6a87, -1),
        ("data_size_auth", 0x6a90, -1),
        ("data_size_noauth", 0x6a91, -1),
        ("unknown", 0x6aff, -10),
        ("unexpected", [0, 0, 0xff], -10),
    ])
    def test_sign_authorized_path_invalid(self, _, device_error, expected_response):
        if type(device_error) == int:
            last_exchange = CommException("msg", device_error)
        else:
            last_exchange = bytes(device_error)
        self.dongle.exchange.side_effect = [last_exchange] # Response to key id, specific error
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.assertEqual((False, expected_response), \
                         self.hsm2dongle.sign_authorized(key_id=key_id,\
                                rsk_tx_receipt="00112233445566778899",\
                                receipt_merkle_proof=["334455", "6677", "aabbccddee"],\
                                btc_tx="aabbccddeeff7788",\
                                input_index=1234))

        self.assert_exchange([\
              [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xd2, 0x04, 0x00, 0x00], # Path and input index
        ])

    def test_sign_authorized_path_unexpected_error_exc(self):
            self.dongle.exchange.side_effect = [
                CommException("", 0xffff), # Response to key id, exception
            ]
            key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
            with self.assertRaises(HSM2DongleError):
                self.hsm2dongle.sign_authorized(key_id=key_id,\
                    rsk_tx_receipt="00112233445566778899",\
                    receipt_merkle_proof=["334455", "6677", "aabbccddee"],\
                    btc_tx="aabbccddeeff7788",\
                    input_index=1234)

            self.assert_exchange([\
                  [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xd2, 0x04, 0x00, 0x00], # Path and input index
            ])

    @patch("ledger.hsm2dongle.HSM2DongleSignature")
    def test_sign_unauthorized_ok(self, HSM2DongleSignatureMock):
        HSM2DongleSignatureMock.return_value = "the-signature"
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x81, 0x55, 0x66, 0x77, 0x88]), # Response to path and hash
        ]
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.assertEqual((True, "the-signature"), \
                         self.hsm2dongle.sign_unauthorized(key_id=key_id,\
                                hash="aabbccddeeff"))

        self.assert_exchange([\
              [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], # Path and hash
        ])
        self.assertEqual([call(bytes([0x55, 0x66, 0x77, 0x88]))], HSM2DongleSignatureMock.call_args_list)

    @patch("ledger.hsm2dongle.HSM2DongleSignature")
    def test_sign_unauthorized_invalid_signature(self, HSM2DongleSignatureMock):
        HSM2DongleSignatureMock.side_effect = ValueError()
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x81, 0x55, 0x66, 0x77, 0x88]), # Response to path and hash
        ]
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.assertEqual((False, -10), \
                         self.hsm2dongle.sign_unauthorized(key_id=key_id,\
                                hash="aabbccddeeff"))

        self.assert_exchange([\
              [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], # Path and hash
        ])
        self.assertEqual([call(bytes([0x55, 0x66, 0x77, 0x88]))], HSM2DongleSignatureMock.call_args_list)

    @parameterized.expand([
        ("data_size", 0x6a87, -5),
        ("data_size_noauth", 0x6a91, -5),
        ("invalid_path", 0x6a8f, -1),
        ("data_size_auth", 0x6a90, -1),
        ("unknown", 0x6aff, -10),
        ("btc_tx", [0, 0, 0x02], -5),
        ("unexpected", [0, 0, 0xaa], -10),
    ])
    def test_sign_unauthorized_dongle_error_result(self, _, device_error, expected_response):
        if type(device_error) == int:
            last_exchange = CommException("msg", device_error)
        else:
            last_exchange = bytes(device_error)
        self.dongle.exchange.side_effect = [last_exchange] # Response to path and hash
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        self.assertEqual((False, expected_response), \
                         self.hsm2dongle.sign_unauthorized(key_id=key_id,\
                                hash="aabbccddeeff"))

        self.assert_exchange([\
              [0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], # Path and hash
        ])

    def test_sign_unauthorized_invalid_hash(self):
        self.assertEqual((False, -5), \
                         self.hsm2dongle.sign_unauthorized(key_id="doesn't matter",\
                                hash="not-a-hex"))

        self.assertFalse(self.dongle.exchange.called)

    def test_get_blockchain_state_ok(self):
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x01, 0x01]) + bytes.fromhex("11"*32), # Response to get best_block
            bytes([0, 0, 0x01, 0x02]) + bytes.fromhex("22"*32), # Response to get newest_valid_block
            bytes([0, 0, 0x01, 0x03]) + bytes.fromhex("33"*32), # Response to get ancestor_block
            bytes([0, 0, 0x01, 0x05]) + bytes.fromhex("44"*32), # Response to get ancestor_receipts_root
            bytes([0, 0, 0x01, 0x81]) + bytes.fromhex("55"*32), # Response to get updating.best_block
            bytes([0, 0, 0x01, 0x82]) + bytes.fromhex("66"*32), # Response to get updating.newest_valid_block
            bytes([0, 0, 0x01, 0x84]) + bytes.fromhex("77"*32), # Response to get updating.next_expected_block
            bytes([0, 0, 0x02]) + bytes.fromhex("112233445566"), # Response to get difficulty
            bytes([0, 0, 0x03, 0x00, 0xff, 0xff]), # Response to get flags
        ]
        self.assertEqual({
            "best_block": "11"*32,
            "newest_valid_block": "22"*32,
            "ancestor_block": "33"*32,
            "ancestor_receipts_root": "44"*32,
            "updating.best_block": "55"*32,
            "updating.newest_valid_block": "66"*32,
            "updating.next_expected_block": "77"*32,
            "updating.total_difficulty": int.from_bytes(bytes.fromhex("112233445566"), byteorder="big", signed=False),
            "updating.in_progress": False,
            "updating.already_validated": True,
            "updating.found_best_block": True,
        }, self.hsm2dongle.get_blockchain_state())

        self.assert_exchange([\
            [0x20, 0x01, 0x01],
            [0x20, 0x01, 0x02],
            [0x20, 0x01, 0x03],
            [0x20, 0x01, 0x05],
            [0x20, 0x01, 0x81],
            [0x20, 0x01, 0x82],
            [0x20, 0x01, 0x84],
            [0x20, 0x02],
            [0x20, 0x03],
        ])

    def test_get_blockchain_state_error_hash(self):
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x01, 0x01]) + bytes.fromhex("11"*32), # Response to get best_block
            bytes([0, 0, 0x01, 0x02]) + bytes.fromhex("22"*32), # Response to get newest_valid_block
            bytes([0, 0, 0x01, 0x03]) + bytes.fromhex("33"*32), # Response to get ancestor_block
            bytes([0, 0, 0x01, 0x05]) + bytes.fromhex("44"*32), # Response to get ancestor_receipts_root
            bytes([0, 0, 0xaa]), # Response to get updating.best_block
        ]

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.get_blockchain_state()

        self.assert_exchange([\
            [0x20, 0x01, 0x01],
            [0x20, 0x01, 0x02],
            [0x20, 0x01, 0x03],
            [0x20, 0x01, 0x05],
            [0x20, 0x01, 0x81],
        ])

    def test_get_blockchain_state_error_difficulty(self):
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x01, 0x01]) + bytes.fromhex("11"*32), # Response to get best_block
            bytes([0, 0, 0x01, 0x02]) + bytes.fromhex("22"*32), # Response to get newest_valid_block
            bytes([0, 0, 0x01, 0x03]) + bytes.fromhex("33"*32), # Response to get ancestor_block
            bytes([0, 0, 0x01, 0x05]) + bytes.fromhex("44"*32), # Response to get ancestor_receipts_root
            bytes([0, 0, 0x01, 0x81]) + bytes.fromhex("55"*32), # Response to get ancestor_receipts_root
            bytes([0, 0, 0x01, 0x82]) + bytes.fromhex("66"*32), # Response to get ancestor_receipts_root
            bytes([0, 0, 0x01, 0x84]) + bytes.fromhex("77"*32), # Response to get ancestor_receipts_root
            CommException("a-message"),
        ]

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.get_blockchain_state()

        self.assert_exchange([\
            [0x20, 0x01, 0x01],
            [0x20, 0x01, 0x02],
            [0x20, 0x01, 0x03],
            [0x20, 0x01, 0x05],
            [0x20, 0x01, 0x81],
            [0x20, 0x01, 0x82],
            [0x20, 0x01, 0x84],
            [0x20, 0x02],
        ])

    def test_get_blockchain_state_error_flags(self):
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x01, 0x01]) + bytes.fromhex("11"*32), # Response to get best_block
            bytes([0, 0, 0x01, 0x02]) + bytes.fromhex("22"*32), # Response to get newest_valid_block
            bytes([0, 0, 0x01, 0x03]) + bytes.fromhex("33"*32), # Response to get ancestor_block
            bytes([0, 0, 0x01, 0x05]) + bytes.fromhex("44"*32), # Response to get ancestor_receipts_root
            bytes([0, 0, 0x01, 0x81]) + bytes.fromhex("55"*32), # Response to get ancestor_receipts_root
            bytes([0, 0, 0x01, 0x82]) + bytes.fromhex("66"*32), # Response to get ancestor_receipts_root
            bytes([0, 0, 0x01, 0x84]) + bytes.fromhex("77"*32), # Response to get ancestor_receipts_root
            bytes([0, 0, 0x02, 0xff]), # Response to get difficulty
            bytes([0, 0, 0x04]), # Response to get flags
        ]

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.get_blockchain_state()

        self.assert_exchange([\
            [0x20, 0x01, 0x01],
            [0x20, 0x01, 0x02],
            [0x20, 0x01, 0x03],
            [0x20, 0x01, 0x05],
            [0x20, 0x01, 0x81],
            [0x20, 0x01, 0x82],
            [0x20, 0x01, 0x84],
            [0x20, 0x02],
            [0x20, 0x03],
        ])

    def test_reset_advance_blockchain_ok(self):
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x02]), # Response
        ]
        self.assertTrue(self.hsm2dongle.reset_advance_blockchain())

        self.assert_exchange([\
            [0x21, 0x01],
        ])

    def test_reset_advance_blockchain_invalid_response(self):
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0xaa]), # Response
        ]
        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.reset_advance_blockchain()

        self.assert_exchange([\
            [0x21, 0x01],
        ])

    def test_reset_advance_blockchain_exception(self):
        self.dongle.exchange.side_effect = [
            CommException("a-message")
        ]
        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.reset_advance_blockchain()

        self.assert_exchange([\
            [0x21, 0x01],
        ])

class TestHSM2DongleAdvanceBlockchain(_TestHSM2DongleBase):
    @parameterized.expand(list_product([
        ("partial_v2.0.x", 0x05, 2),
        ("total_v2.0.x", 0x06, 1),
        ("partial_v2.1.x", 0x05, 2),
        ("total_v2.1.x", 0x06, 1),
    ], [
        (HSM2FirmwareVersion(2, 0, 5),),
        (HSM2FirmwareVersion(2, 1, 7),),
    ]))
    @patch("ledger.hsm2dongle.coinbase_tx_get_hash")
    @patch("ledger.hsm2dongle.get_coinbase_txn")
    @patch("ledger.hsm2dongle.rlp_mm_payload_size")
    def test_advance_blockchain_ok(self, _, device_response, expected_response, dongle_app_version, mmplsize_mock, get_cb_txn_mock, cb_txn_get_hash_mock):
        mmplsize_mock.side_effect = lambda h: len(h)//8
        get_cb_txn_mock.side_effect = lambda h: { "cb_txn": h }
        cb_txn_get_hash_mock.side_effect = lambda h: (bytes([len(h["cb_txn"])//5])*4).hex()
        blocks_spec = [
            # (block bytes, chunk size)
            (bytes(map(lambda b: b % 256, range(300))), 80),
            (bytes(map(lambda b: b % 256, range(250))), 100),
            (bytes(map(lambda b: b % 256, range(140))), 50),
        ]

        self.dongle.exchange.side_effect = [bs for excs in map(lambda s: self.spec_to_exchange(s), blocks_spec) for bs in excs] + \
            [bytes([0, 0, device_response])] # Success response

        blocks_hex = list(map(lambda bs: bs[0].hex(), blocks_spec))
        self.assertEqual((True, expected_response), self.hsm2dongle.advance_blockchain(blocks_hex, dongle_app_version))

        expect_cb_txn_hash = dongle_app_version >= HSM2FirmwareVersion(2, 1, 0)

        self.assert_exchange([\
            [0x10, 0x02, 0x00, 0x00, 0x00, 0x03], # Init, 3 blocks
            [0x10, 0x03, 0x00, 0x4b] + ([0x78, 0x78, 0x78, 0x78] if expect_cb_txn_hash else []), # Block #1 meta
            [0x10, 0x04] + list(blocks_spec[0][0][80*0:80*1]), # Block #1 chunk
            [0x10, 0x04] + list(blocks_spec[0][0][80*1:80*2]), # Block #1 chunk
            [0x10, 0x04] + list(blocks_spec[0][0][80*2:80*3]), # Block #1 chunk
            [0x10, 0x04] + list(blocks_spec[0][0][80*3:80*4]), # Block #1 chunk
            [0x10, 0x03, 0x00, 0x3e] +([0x64, 0x64, 0x64, 0x64] if expect_cb_txn_hash else []), # Block #2 meta
            [0x10, 0x04] + list(blocks_spec[1][0][100*0:100*1]), # Block #2 chunk
            [0x10, 0x04] + list(blocks_spec[1][0][100*1:100*2]), # Block #2 chunk
            [0x10, 0x04] + list(blocks_spec[1][0][100*2:100*3]), # Block #2 chunk
            [0x10, 0x03, 0x00, 0x23] + ([0x38, 0x38, 0x38, 0x38] if expect_cb_txn_hash else []), # Block #3 meta
            [0x10, 0x04] + list(blocks_spec[2][0][50*0:50*1]), # Block #2 chunk
            [0x10, 0x04] + list(blocks_spec[2][0][50*1:50*2]), # Block #3 chunk
            [0x10, 0x04] + list(blocks_spec[2][0][50*2:50*3]), # Block #3 chunk
        ])

    @parameterized.expand(list_product([
        ("prot_invalid", 0x6b87, -4),
        ("rlp_invalid", 0x6b88, -5),
        ("block_too_old", 0x6b89, -5),
        ("block_too_short", 0x6b8a, -5),
        ("parent_hash_invalid", 0x6b8b, -5),
        ("block_num_invalid", 0x6b8d, -5),
        ("block_diff_invalid", 0x6b8e, -5),
        ("umm_root_invalid", 0x6b8f, -5),
        ("btc_header_invalid", 0x6b90, -5),
        ("merkle_proof_invalid", 0x6b91, -5),
        ("btc_cb_txn_invalid", 0x6b92, -6),
        ("mm_rlp_len_mismatch", 0x6b93, -5),
        ("btc_diff_mismatch", 0x6b94, -6),
        ("merkle_proof_mismatch", 0x6b95, -6),
        ("mm_hash_mismatch", 0x6b96, -6),
        ("merkle_proof_overflow", 0x6b97, -5),
        ("cb_txn_overflow", 0x6b98, -5),
        ("buffer_overflow", 0x6b99, -5),
        ("chain_mismatch", 0x6b9a, -7),
        ("total_diff_overflow", 0x6b9b, -8),
        ("cb_txn_hash_mismatch", 0x6b9d, -6),
        ("unexpected", 0x6bff, -10),
        ("error_response", bytes([0, 0, 0xff]), -10),
    ], [
        (HSM2FirmwareVersion(2, 0, 5),),
        (HSM2FirmwareVersion(2, 1, 7),),
    ]))
    @patch("ledger.hsm2dongle.coinbase_tx_get_hash")
    @patch("ledger.hsm2dongle.get_coinbase_txn")
    @patch("ledger.hsm2dongle.rlp_mm_payload_size")
    def test_advance_blockchain_chunk_error_result(self, _, error_code, response, dongle_app_version, mmplsize_mock, get_cb_txn_mock, cb_txn_get_hash_mock):
        mmplsize_mock.side_effect = lambda h: len(h)//8
        get_cb_txn_mock.side_effect = lambda h: { "cb_txn": h }
        cb_txn_get_hash_mock.side_effect = lambda h: (bytes([len(h["cb_txn"])//5])*4).hex()
        blocks_spec = [
            # (block bytes, chunk size)
            (bytes(map(lambda b: b % 256, range(300))), 80),
            (bytes(map(lambda b: b % 256, range(250))), 100),
            (bytes(map(lambda b: b % 256, range(140))), 50),
        ]

        side_effect = [bs for excs in map(lambda s: self.spec_to_exchange(s), blocks_spec) for bs in excs]
        # Make the second chunk of the second block fail
        exchange_index = 1 + (300//80+2) + 2 # Init + first block meta & chunks + second block meta & first chunk
        if type(error_code) == bytes:
            side_effect[exchange_index] = error_code
        else:
            side_effect[exchange_index] = CommException("a-message", error_code)
        side_effect = side_effect[:exchange_index+1]
        self.dongle.exchange.side_effect = side_effect

        blocks_hex = list(map(lambda bs: bs[0].hex(), blocks_spec))
        self.assertEqual((False, response), self.hsm2dongle.advance_blockchain(blocks_hex, dongle_app_version))

        expect_cb_txn_hash = dongle_app_version >= HSM2FirmwareVersion(2, 1, 0)

        self.assert_exchange([\
            [0x10, 0x02, 0x00, 0x00, 0x00, 0x03], # Init, 3 blocks
            [0x10, 0x03, 0x00, 0x4b] + ([0x78, 0x78, 0x78, 0x78] if expect_cb_txn_hash else []), # Block #1 meta
            [0x10, 0x04] + list(blocks_spec[0][0][80*0:80*1]), # Block #1 chunk
            [0x10, 0x04] + list(blocks_spec[0][0][80*1:80*2]), # Block #1 chunk
            [0x10, 0x04] + list(blocks_spec[0][0][80*2:80*3]), # Block #1 chunk
            [0x10, 0x04] + list(blocks_spec[0][0][80*3:80*4]), # Block #1 chunk
            [0x10, 0x03, 0x00, 0x3e] + ([0x64, 0x64, 0x64, 0x64] if expect_cb_txn_hash else []), # Block #2 meta
            [0x10, 0x04] + list(blocks_spec[1][0][100*0:100*1]), # Block #2 chunk
            [0x10, 0x04] + list(blocks_spec[1][0][100*1:100*2]), # Block #2 chunk
        ])

    @parameterized.expand(list_product([
        ("prot_invalid", 0x6b87, -3),
        ("unexpected", 0x6bff, -10),
        ("error_response", bytes([0, 0, 0xff]), -10),
    ], [
        (HSM2FirmwareVersion(2, 0, 5),),
        (HSM2FirmwareVersion(2, 1, 7),),
    ]))
    @patch("ledger.hsm2dongle.coinbase_tx_get_hash")
    @patch("ledger.hsm2dongle.get_coinbase_txn")
    @patch("ledger.hsm2dongle.rlp_mm_payload_size")
    def test_advance_blockchain_metadata_error_result(self, _, error_code, response, dongle_app_version, mmplsize_mock, get_cb_txn_mock, cb_txn_get_hash_mock):
        mmplsize_mock.side_effect = lambda h: len(h)//8
        get_cb_txn_mock.side_effect = lambda h: { "cb_txn": h }
        cb_txn_get_hash_mock.side_effect = lambda h: (bytes([len(h["cb_txn"])//5])*4).hex()
        blocks_spec = [
            # (block bytes, chunk size)
            (bytes(map(lambda b: b % 256, range(300))), 80),
            (bytes(map(lambda b: b % 256, range(250))), 100),
            (bytes(map(lambda b: b % 256, range(140))), 50),
        ]

        side_effect = [bs for excs in map(lambda s: self.spec_to_exchange(s), blocks_spec) for bs in excs]
        # Make the metadata of the third block fail
        exchange_index = 1 + (300//80+2) + (250//100+2) # Init + first and second block meta & chunks + third block meta
        if type(error_code) == bytes:
            side_effect[exchange_index] = error_code
        else:
            side_effect[exchange_index] = CommException("a-message", error_code)
        side_effect = side_effect[:exchange_index+1]
        self.dongle.exchange.side_effect = side_effect

        blocks_hex = list(map(lambda bs: bs[0].hex(), blocks_spec))
        self.assertEqual((False, response), self.hsm2dongle.advance_blockchain(blocks_hex, dongle_app_version))

        expect_cb_txn_hash = dongle_app_version >= HSM2FirmwareVersion(2, 1, 0)

        self.assert_exchange([\
            [0x10, 0x02, 0x00, 0x00, 0x00, 0x03], # Init, 3 blocks
            [0x10, 0x03, 0x00, 0x4b] + ([0x78, 0x78, 0x78, 0x78] if expect_cb_txn_hash else []), # Block #1 meta
            [0x10, 0x04] + list(blocks_spec[0][0][80*0:80*1]), # Block #1 chunk
            [0x10, 0x04] + list(blocks_spec[0][0][80*1:80*2]), # Block #1 chunk
            [0x10, 0x04] + list(blocks_spec[0][0][80*2:80*3]), # Block #1 chunk
            [0x10, 0x04] + list(blocks_spec[0][0][80*3:80*4]), # Block #1 chunk
            [0x10, 0x03, 0x00, 0x3e] + ([0x64, 0x64, 0x64, 0x64] if expect_cb_txn_hash else []), # Block #2 meta
            [0x10, 0x04] + list(blocks_spec[1][0][100*0:100*1]), # Block #2 chunk
            [0x10, 0x04] + list(blocks_spec[1][0][100*1:100*2]), # Block #2 chunk
            [0x10, 0x04] + list(blocks_spec[1][0][100*2:100*3]), # Block #2 chunk
            [0x10, 0x03, 0x00, 0x23] + ([0x38, 0x38, 0x38, 0x38] if expect_cb_txn_hash else []), # Block #3 meta
        ])

    @patch("ledger.hsm2dongle.rlp_mm_payload_size")
    def test_advance_blockchain_metadata_error_generating(self, mmplsize_mock):
        mmplsize_mock.side_effect = ValueError()
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x03])
        ]

        self.assertEqual((False, -2), self.hsm2dongle.advance_blockchain(["first-block", "second-block"], 'an-app-version'))

        self.assert_exchange([\
            [0x10, 0x02, 0x00, 0x00, 0x00, 0x02], # Init, 2 blocks
        ])
        self.assertEqual([call("first-block")], mmplsize_mock.call_args_list)

    @parameterized.expand([
        ("prot_invalid", CommException("a-message", 0x6b87), -1),
        ("unexpected", CommException("a-message", 0x6bff), -10),
        ("invalid_response", bytes([0, 0, 0xff]), -10),
    ])
    def test_advance_blockchain_init_error(self, _, error, response):
        self.dongle.exchange.side_effect = [error]

        self.assertEqual((False, response), self.hsm2dongle.advance_blockchain(["first-block", "second-block"], 'an-app-version'))

        self.assert_exchange([\
            [0x10, 0x02, 0x00, 0x00, 0x00, 0x02], # Init, 2 blocks
        ])

class TestHSM2DongleUpdateAncestor(_TestHSM2DongleBase):
    @patch("ledger.hsm2dongle.remove_mm_fields_if_present")
    @patch("ledger.hsm2dongle.rlp_mm_payload_size")
    def test_update_ancestor_ok(self, mmplsize_mock, rmvflds_mock):
        rmvflds_mock.side_effect = lambda h: h[:-bytes.fromhex(h)[-1]*2]
        mmplsize_mock.side_effect = lambda h: len(h)//8
        blocks_spec = [
            # (block bytes, chunk size)
            (bytes(map(lambda b: b % 256, range(300))) + bytes.fromhex("aabbccddeeff0011220a"), 80),
            (bytes(map(lambda b: b % 256, range(250))) + bytes.fromhex("1122334405"), 100),
            (bytes(map(lambda b: b % 256, range(130))) + bytes.fromhex("334455aabbccdd2211982311aacdfe10"), 50),
        ]

        self.dongle.exchange.side_effect = [bs for excs in map(lambda s: self.spec_to_exchange(s,trim=True), blocks_spec) for bs in excs] + \
            [bytes([0, 0, 0x05])] # Success response

        blocks_hex = list(map(lambda bs: bs[0].hex(), blocks_spec))
        self.assertEqual((True, 1), self.hsm2dongle.update_ancestor(blocks_hex, 'an-app-version'))

        self.assert_exchange([\
            [0x30, 0x02, 0x00, 0x00, 0x00, 0x03], # Init, 3 blocks
            [0x30, 0x03, 0x00, 0x4b], # Block #1 meta
            [0x30, 0x04] + list(blocks_spec[0][0][80*0:80*1]), # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*1:80*2]), # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*2:80*3]), # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*3:80*4][:-blocks_spec[0][0][-1]]), # Block #1 chunk
            [0x30, 0x03, 0x00, 0x3e], # Block #2 meta
            [0x30, 0x04] + list(blocks_spec[1][0][100*0:100*1]), # Block #2 chunk
            [0x30, 0x04] + list(blocks_spec[1][0][100*1:100*2]), # Block #2 chunk
            [0x30, 0x04] + list(blocks_spec[1][0][100*2:100*3][:-blocks_spec[1][0][-1]]), # Block #2 chunk
            [0x30, 0x03, 0x00, 0x20], # Block #3 meta
            [0x30, 0x04] + list(blocks_spec[2][0][50*0:50*1]), # Block #2 chunk
            [0x30, 0x04] + list(blocks_spec[2][0][50*1:50*2]), # Block #3 chunk
            [0x30, 0x04] + list(blocks_spec[2][0][50*2:50*3][:-blocks_spec[2][0][-1]]), # Block #3 chunk
        ])

    @parameterized.expand([
        ("prot_invalid", 0x6b87, -4),
        ("rlp_invalid", 0x6b88, -5),
        ("block_too_old", 0x6b89, -5),
        ("block_too_short", 0x6b8a, -5),
        ("parent_hash_invalid", 0x6b8b, -5),
        ("receipt_root_invalid", 0x6b8c, -5),
        ("block_num_invalid", 0x6b8d, -5),
        ("btc_header_invalid", 0x6b90, -5),
        ("mm_rlp_len_mismatch", 0x6b93, -5),
        ("buffer_overflow", 0x6b99, -5),
        ("chain_mismatch", 0x6b9a, -6),
        ("ancestor_tip_mismatch", 0x6b9c, -7),
        ("unexpected", 0x6bff, -10),
        ("error_response", bytes([0, 0, 0xff]), -10),
    ])
    @patch("ledger.hsm2dongle.remove_mm_fields_if_present")
    @patch("ledger.hsm2dongle.rlp_mm_payload_size")
    def test_update_ancestor_chunk_error_result(self, _, error_code, response, mmplsize_mock, rmvflds_mock):
        rmvflds_mock.side_effect = lambda h: h
        mmplsize_mock.side_effect = lambda h: len(h)//8
        blocks_spec = [
            # (block bytes, chunk size)
            (bytes(map(lambda b: b % 256, range(300))), 80),
            (bytes(map(lambda b: b % 256, range(250))), 100),
            (bytes(map(lambda b: b % 256, range(140))), 50),
        ]

        side_effect = [bs for excs in map(lambda s: self.spec_to_exchange(s), blocks_spec) for bs in excs]
        # Make the second chunk of the second block fail
        exchange_index = 1 + (300//80+2) + 2 # Init + first block meta & chunks + second block meta & first chunk
        if type(error_code) == bytes:
            side_effect[exchange_index] = error_code
        else:
            side_effect[exchange_index] = CommException("a-message", error_code)
        side_effect = side_effect[:exchange_index+1]
        self.dongle.exchange.side_effect = side_effect

        blocks_hex = list(map(lambda bs: bs[0].hex(), blocks_spec))
        self.assertEqual((False, response), self.hsm2dongle.update_ancestor(blocks_hex, 'an-app-version'))

        self.assert_exchange([\
            [0x30, 0x02, 0x00, 0x00, 0x00, 0x03], # Init, 3 blocks
            [0x30, 0x03, 0x00, 0x4b], # Block #1 meta
            [0x30, 0x04] + list(blocks_spec[0][0][80*0:80*1]), # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*1:80*2]), # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*2:80*3]), # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*3:80*4]), # Block #1 chunk
            [0x30, 0x03, 0x00, 0x3e], # Block #2 meta
            [0x30, 0x04] + list(blocks_spec[1][0][100*0:100*1]), # Block #2 chunk
            [0x30, 0x04] + list(blocks_spec[1][0][100*1:100*2]), # Block #2 chunk
        ])

    @parameterized.expand([
        ("prot_invalid", 0x6b87, -3),
        ("unexpected", 0x6bff, -10),
        ("error_response", bytes([0, 0, 0xff]), -10),
    ])
    @patch("ledger.hsm2dongle.remove_mm_fields_if_present")
    @patch("ledger.hsm2dongle.rlp_mm_payload_size")
    def test_update_ancestor_metadata_error_result(self, _, error_code, response, mmplsize_mock, rmvflds_mock):
        rmvflds_mock.side_effect = lambda h: h
        mmplsize_mock.side_effect = lambda h: len(h)//8
        blocks_spec = [
            # (block bytes, chunk size)
            (bytes(map(lambda b: b % 256, range(300))), 80),
            (bytes(map(lambda b: b % 256, range(250))), 100),
            (bytes(map(lambda b: b % 256, range(140))), 50),
        ]

        side_effect = [bs for excs in map(lambda s: self.spec_to_exchange(s), blocks_spec) for bs in excs]
        # Make the metadata of the third block fail
        exchange_index = 1 + (300//80+2) + (250//100+2) # Init + first and second block meta & chunks + third block meta
        if type(error_code) == bytes:
            side_effect[exchange_index] = error_code
        else:
            side_effect[exchange_index] = CommException("a-message", error_code)
        side_effect = side_effect[:exchange_index+1]
        self.dongle.exchange.side_effect = side_effect

        blocks_hex = list(map(lambda bs: bs[0].hex(), blocks_spec))
        self.assertEqual((False, response), self.hsm2dongle.update_ancestor(blocks_hex, 'an-app-version'))

        self.assert_exchange([\
            [0x30, 0x02, 0x00, 0x00, 0x00, 0x03], # Init, 3 blocks
            [0x30, 0x03, 0x00, 0x4b], # Block #1 meta
            [0x30, 0x04] + list(blocks_spec[0][0][80*0:80*1]), # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*1:80*2]), # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*2:80*3]), # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*3:80*4]), # Block #1 chunk
            [0x30, 0x03, 0x00, 0x3e], # Block #2 meta
            [0x30, 0x04] + list(blocks_spec[1][0][100*0:100*1]), # Block #2 chunk
            [0x30, 0x04] + list(blocks_spec[1][0][100*1:100*2]), # Block #2 chunk
            [0x30, 0x04] + list(blocks_spec[1][0][100*2:100*3]), # Block #2 chunk
            [0x30, 0x03, 0x00, 0x23], # Block #3 meta
        ])

    @patch("ledger.hsm2dongle.remove_mm_fields_if_present")
    @patch("ledger.hsm2dongle.rlp_mm_payload_size")
    def test_update_ancestor_metadata_error_generating(self, mmplsize_mock, rmvflds_mock):
        rmvflds_mock.side_effect = lambda h: h
        mmplsize_mock.side_effect = ValueError()
        self.dongle.exchange.side_effect = [
            bytes([0, 0, 0x03])
        ]

        self.assertEqual((False, -2), self.hsm2dongle.update_ancestor(["first-block", "second-block"], 'an-app-version'))

        self.assert_exchange([\
            [0x30, 0x02, 0x00, 0x00, 0x00, 0x02], # Init, 2 blocks
        ])
        self.assertEqual([call("first-block")], mmplsize_mock.call_args_list)

    @parameterized.expand([
        ("prot_invalid", CommException("a-message", 0x6b87), -1),
        ("unexpected", CommException("a-message", 0x6bff), -10),
        ("invalid_response", bytes([0, 0, 0xff]), -10),
    ])
    @patch("ledger.hsm2dongle.remove_mm_fields_if_present")
    def test_update_ancestor_init_error(self, _, error, response, rmvflds_mock):
        rmvflds_mock.side_effect = lambda h: h
        self.dongle.exchange.side_effect = [error]

        self.assertEqual((False, response), self.hsm2dongle.update_ancestor(["first-block", "second-block"], 'an-app-version'))

        self.assert_exchange([\
            [0x30, 0x02, 0x00, 0x00, 0x00, 0x02], # Init, 2 blocks
        ])

    @patch("ledger.hsm2dongle.remove_mm_fields_if_present")
    def test_update_ancestor_remove_mmfields_exception(self, rmvflds_mock):
        rmvflds_mock.side_effect = ValueError("an error")

        self.assertEqual((False, -8), self.hsm2dongle.update_ancestor(["first-block", "second-block"], 'an-app-version'))

        self.assert_exchange([])
