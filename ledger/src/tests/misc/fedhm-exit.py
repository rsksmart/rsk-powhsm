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

	print "[I] Finding mode"
	apdu = bytearray([RSK_MSG,RSK_MODE_CMD,0x41,0x41])
	apdu_rcv = dongle.exchange(apdu)
	if apdu_rcv[1]==RSK_MODE_BOOTLOADER:
		print "[I] MODE: Bootloader"
		print "[I] Sending echo"
		apdu = bytearray([RSK_MSG,RSK_ECHO_CMD,0x41,0x41])
		apdu_rcv = dongle.exchange(apdu)
		for i in range(len(apdu)):
			if apdu[i]!=apdu_rcv[i]:
				print "[E] Echo Error!"
				print "[E] Sent:"+repr(apdu)
				print "[E] Received:"+repr(apdu_rcv)
		print "[I] Echo message Successful"
		if options.wipe==True:
			print "[I] Wiping device"
			apdu = bytearray([RSK_MSG,RSK_WIPE])
			apdu_rcv = dongle.exchange(apdu)
			print "[I] Ready..exit"
			exit(0)
		print "[I] Is device Onboarded?"
		apdu = bytearray([RSK_MSG,RSK_IS_ONBOARD])
		apdu_rcv = dongle.exchange(apdu)
		if apdu_rcv[1]==1:
			print "[I] Yes"
		else:
			print "[I] No, exiting..."
			exit(0)


		exit(0)
	if len(apdu_rcv)>1:
		if apdu_rcv[1]==RSK_MODE_APP:
			print "[I] MODE: Application."
			apdu = bytearray([RSK_MSG,RSK_END_CMD,0x00,0x00])
			try:
				apdu_rcv = dongle.exchange(apdu,timeout=0.1)
			except: pass

