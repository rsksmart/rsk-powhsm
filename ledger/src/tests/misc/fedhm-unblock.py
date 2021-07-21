if __name__ == '__main__':
        from ledgerblue.ecWrapper import PrivateKey
        from ledgerblue.comm import getDongle
        from ledgerblue.deployed import getDeployedSecretV1, getDeployedSecretV2
        from ledgerblue.hexLoader import HexLoader
	from ledgerblue.commException import CommException
	from secp256k1 import PublicKey
        import binascii
        import sys,os,random,string

	# parse arguments
	from optparse import OptionParser
	parser = OptionParser()
	parser.add_option("-l", "--logentry",type="int",dest="logentry")
	parser.add_option("-w", "--wipe",action="store_true",dest="wipe",default=False)
	parser.add_option("-p","--pin",dest="PIN",help="Save PIN to file. (default 'pin.txt')",default="pin.txt")
	parser.add_option("-n","--noautoexec",action="store_true",dest="autoexec",help="Don't execute sign app",default=False)
	(options,args) = parser.parse_args()
		

	RSK_MSG=0x80
	RSK_PIN_CMD=0x41
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
		print "[I] loading PIN..."
		pin= open(options.PIN).read()
		print "[I] Sending PIN..."
		apdu = bytearray([0,0,0,0])
		for i in range(len(pin)):
			apdu[0]=RSK_MSG
			apdu[1]=RSK_PIN_CMD
			apdu[2]=i
			apdu[3]=pin[i]
			apdu_rcv = dongle.exchange(apdu)

		print "[I] PIN sent, unlocking..."
		apdu = bytearray([RSK_MSG,RSK_TEST_PIN_CMD,0x00,0x00])
		apdu_rcv = dongle.exchange(apdu,timeout=0.1)

		if (apdu_rcv[2]==0):
			print "[E] WRONG PIN! exiting..."
			exit(0)
		else:
			print "[I] PIN accepted."
			if (os.path.isfile("./changePIN")):
				print "[I] First use detected. Forcing a change of PIN."
				pin = '55555555'#.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(8))
				a=open(options.PIN,"wb")
				a.write(pin)
				a.close()
				print "[I] New pin: "+ pin
				print "[I] Sending PIN..."
				apdu = bytearray([0,0,0,0])
				pin = chr(len(pin))+pin
				for i in range(len(pin)):
					apdu[0]=RSK_MSG
					apdu[1]=RSK_PIN_CMD
					apdu[2]=i
					apdu[3]=pin[i]
					apdu_rcv = dongle.exchange(apdu)
				apdu[0]=RSK_MSG
				apdu[1]=RSK_NEWPIN
				apdu_rcv = dongle.exchange(apdu)
				os.unlink("./changePIN")
				print "[I] Please Please disconnect/reconnect the ledger."
				exit(0)

		apdu = bytearray([RSK_MSG,0xff,0x00,0x00])
		if options.autoexec==True:
			apdu = bytearray([RSK_MSG,RSK_END_NOSIG_CMD,0x00,0x00])
			print "[I] Note: Not executing sign app (For firmware update)."
		try:
			apdu_rcv = dongle.exchange(apdu,timeout=0.1)
		except: pass

		exit(0)
	if len(apdu_rcv)>1:
		if apdu_rcv[1]==RSK_MODE_APP:
			print "[I] MODE: Application. Already unlocked."
			# return log
			if options.logentry != None:
				print "[I] Reading log entry %d" % options.logentry
				apdu = bytearray([RSK_MSG,RSK_GET_LOG,options.logentry,0x41])
				apdu_rcv = dongle.exchange(apdu)
				exit(0)



