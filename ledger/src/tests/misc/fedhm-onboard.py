# fedhm personalization v1.1
# run with:
#     $ python fedhm-onboard.py
# for options:
#     $ python fedhm-onboard.py -h

import random,string,time
from optparse import OptionParser
import os.path
from ledgerblue.ecWrapper import PrivateKey
from ledgerblue.comm import getDongle
from ledgerblue.deployed import getDeployedSecretV1, getDeployedSecretV2
from ledgerblue.hexLoader import HexLoader
from ledgerblue.commException import CommException


RSK_MSG=0x80
RSK_PIN_CMD=0x41
RSK_SEED_CMD=0x44
RSK_ECHO_CMD=0x02
RSK_UNLOCK_CMD=0xff
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

def genRND():
	print "[I] Generating host random"
	random.seed()
	seedrnd=""
	for i in range(32):
		seedrnd+=chr(random.randint(0,255))
	return seedrnd

def onboard(seedrnd,pin):
	print "[I] Connecting to ledger..."
	print "[I] dongle found: %s" % repr(dongle)

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
		print "[I] Is device Onboarded?"
		apdu = bytearray([RSK_MSG,RSK_IS_ONBOARD])
		apdu_rcv = dongle.exchange(apdu)
		if apdu_rcv[1]==1:
			print "[I] Yes, wiping"
		else:
			print "[I] No, onboarding..."
		print "[I] Sending RND"
		apdu = bytearray([0,0,0,0])
		for i in range(len(seedrnd)):
			apdu[0]=RSK_MSG
			apdu[1]=RSK_SEED_CMD
			apdu[2]=i
			apdu[3]=ord(seedrnd[i])
			apdu_rcv = dongle.exchange(apdu)
		print "[I] Sending PIN..."
		apdu = bytearray([0,0,0,0])
		pin = chr(len(pin))+pin
		for i in range(len(pin)):
			apdu[0]=RSK_MSG
			apdu[1]=RSK_PIN_CMD
			apdu[2]=i
			apdu[3]=pin[i]
			apdu_rcv = dongle.exchange(apdu)
		print "[I] Initializing device"
		apdu = bytearray([RSK_MSG,RSK_WIPE])
		apdu_rcv = dongle.exchange(apdu)
		print "[I] Saving backup..."
		a=open("seedbackup.bin","wb")
		a.write(apdu_rcv[3:3+32+33])
		a.close()
		a=open("changePIN","wb")
		a.close()
		print "[I] Ready..exit"



def generate(numericPin=False):
	print "[Q] Auto-generate 8-character Pin?"
	a=raw_input("Enter Y to autogenerate, N to input from keyboard>")
	if a[0].lower()=='N':
		pincorrect=False
		while(pincorrect==False):
			print "[Q] Enter 8-number Pin"
			a=raw_input(">")
			print "[Q] Re-Enter 8-number Pin"
			b=raw_input(">")
			if not (a == b):
				print "[E] PIN differ"
			else:	
				if len(a)!=8:
					print "[E] PIN lenght must be 8"
				else:	
					pincorrect=True
					pin=a
	else:   #Generate PIN
		pin=""
		random.seed()
		if numericPin==True:
			for i in range(8):
				pin+="%d" % random.randint(0,9)
		else:	pin = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(8))
	print "[I] Your PIN is: %s" % pin
	# Save PIN
	a=open(options.PIN,"wb")
	a.write(pin)
	a.close()
	print "[I] PIN saved to %s" % options.PIN
	return(pin)

def	load(pin):
	print "[I] Loading pin from %s" % pin
	return(open(pin).read())
	
if __name__ == '__main__':
   # options parsing
	parser = OptionParser()
	parser.add_option("-p","--pin",dest="PIN",help="Save PIN to file. (default 'pin.txt')",default="pin.txt")
	parser.add_option("-n","--numericpin",dest="numericPIN",action="store_true",help="Generate all-numeric PIN. (default NO)",default=False)
	(options, args) = parser.parse_args()
	if (os.path.isfile(options.PIN)):
		print "[I] Pin file already exits. Load?"
		a=raw_input("Enter Y to load, N to create> ")
		if a[0].lower()=='n':
			pin=generate(options.numericPIN)
		else:	pin=load(options.PIN)
	else: pin=generate()
	## Mock send to ledger
	print "[I] WARNING: This will wipe the ledger"
	print "[I] Initialize send Pin to Ledger?"
	a=raw_input("Enter Y to initialize, N to exit> ")
	if a[0].lower()=='y':
		seedrng=genRND()
		onboard(seedrng,pin)
	print "[I] Please disconnect/reconnect the ledger"
