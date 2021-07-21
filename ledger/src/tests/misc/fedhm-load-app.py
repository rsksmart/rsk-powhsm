if __name__ == '__main__':
        from ledgerblue.ecWrapper import PrivateKey
        from ledgerblue.comm import getDongle
        from ledgerblue.deployed import getDeployedSecretV1, getDeployedSecretV2
        from ledgerblue.hexLoader import HexLoader
	from ledgerblue.commException import CommException
	from secp256k1 import PublicKey
        import binascii
        import sys

	RSK_MSG=0x80
	RSK_PIN_CMD=0x41
	RSK_END_CMD=0xFF
	RSK_ECHO_CMD=0x02
	RSK_TEST_PIN_CMD=0xfe
	RSK_END_NOSIG_CMD=0xfa
	RSK_DBG1_CMD=0x42
	RSK_MODE_CMD=0x43
	RSK_MODE_BOOTLOADER=0x02
	RSK_MODE_APP=0x03
	RSK_GET_LOG=0x05
	RSK_IS_ONBOARD=0x06
	RSK_WIPE=0x07
	RSK_NEWPIN=0x08

        dongle = getDongle(True)
	dongle.debug=True
	print dongle
	apdu = bytearray([0xE0,0xD2,0xff,0])
	try:
		apdu_rcv = dongle.exchange(apdu,timeout=1.1)
	except: pass

