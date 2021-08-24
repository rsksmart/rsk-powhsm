#
# fedhm ledger server v1.3
# needs secp256k1, install with:
#     $ sudo pip install secp256k1
# run with:
#     $ python fedhm-mockup.py
# for options:
#     $ python fedhm-mockup.py -h
#
#
# example client test:
#
#Using Ledger Blue Nano S for BTC https://github.com/LedgerHQ/blue-sample-apps/tree/master/blue-app-samplesign
# Emulator https://github.com/LedgerHQ/blue-sample-apps/blob/master/blue-app-samplesign/src/main.c#L514
#For etherium it uses a diferent ledger with CLA 0xE0
"""
guest@guest-thinkpad:~$ telnet localhost 9999
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
{"command":"version"}
{"errorcode": "0", "version": "2"}
{"command":"getPubKey"}

getPubKey example:
{"command":"getPubKey","version":1,"keyId":"m/44'/1'/0'/0/0","auth":""}
"""
#
#

import traceback
import json
import SocketServer
import sys
import binascii
import time
import struct
import os
from optparse import OptionParser
from secp256k1 import PublicKey
from ledgerblue.ecWrapper import PrivateKey
from ledgerblue.comm import getDongle
from ledgerblue.deployed import getDeployedSecretV1, getDeployedSecretV2
from ledgerblue.hexLoader import HexLoader
from ledgerblue.commException import CommException



# Command Constants
version = 1
CLA = 0x80
INS_SIGN = 0x02
INS_GET_PUBLIC_KEY = 0x04
RSK_GET_LOG = 0x05
RSK_IS_ONBOARD = 0x06
P1_LAST = 0x80
P1_MORE = 0x00
P1_PATH = 0x70
RSK_MODE_CMD = 0x43
RSK_MODE_APP = 0x03
RSK_MODE_BOOTLOADER=0x02

RSK_MSG=0x80
RSK_PIN_CMD=0x41
RSK_ECHO_CMD=0x02
RSK_UNLOCK_CMD=0xff
RSK_DBG1_CMD=0x42
RSK_GET_LOG=0x05
RSK_IS_ONBOARD=0x06
RSK_WIPE=0x07



    # Sennd raw APDU to emulator
def exchange(data):
    return dongle.exchange(data)

def getBody(result):
    StatusWord1 = result[-2].encode('hex')
    StatusWord2 = result[-1].encode('hex')
    #more information at https://www.eftlab.co.uk/index.php/site-map/knowledge-base/118-apdu-response-list
    if StatusWord1 == '64':
        print "State of non-volatile memory unchanged"
    if StatusWord1 == '65':
        print "State of non-volatile memory changed"
    if StatusWord1 == '67':
        print "Incorrect length"
    if StatusWord1 == '68':
        print "Functions in CLA not supported"
    if StatusWord1 == '69':
        print "Command not allowed"
    if StatusWord1 == '6a':
        print "Incorrect parameter P1 or P2"
    if StatusWord1 == '6c':
        print "Wrong length Le"
    if StatusWord1 == '6e':
        print "Instruction class not supported "
    if StatusWord1 == '6f':
        print "Internal exception"
    if (StatusWord1 != '90' or StatusWord1 !='91') and StatusWord2 != '00':
        raise ValueError('HSM returned an error with the following status word: ' + StatusWord1 + StatusWord2)
    data = result[:-2]
    return data

# Send command to emulator
def sendCommand(command,data=""):
      cmd=struct.pack('BB',CLA,command)
      cmd+=bytes(data)
      print "sendCommand(): Sending: " + cmd.encode('hex')
      #s=""
      #for c in cmd: s += "\\x%02x" % ord(c)
      #print "sendCommand(): Sending: %s" % s
      result=str(dongle.exchange(cmd))+"\x90\x00"
      print "sendCommand(): Received: " + result.encode('hex')
      #s=""
      #for c in result: s+="\\x%02x" % ord(c)
      #print "sendCommand(): Received: %s" % s
      body = getBody(result)
      return body

## sign a specified message (textToSign) using the specified bip44 path (keyId)
def sign(textToSign,keyId):
    offset = 0
    #First, send keypath
    apdu = chr(CLA) + chr(INS_SIGN) + chr(P1_PATH) + bytes(keyId)
    exchange(apdu)
    #more information at https://coranos.github.io/blue-app-neo/docs/index.html#sign_tx_seq
    #and http://www.tml.tkk.fi/Studies/T-110.497/2003/lecture4.pdf
    #and https://github.com/LedgerHQ/blue-sample-apps/blob/master/blue-app-samplesign/demo.py
    while offset != len(textToSign):
        if (len(textToSign) - offset) > 255:
            chunk = textToSign[offset : offset + 255] 
        else:
            chunk = textToSign[offset:]
        if (offset + len(chunk)) == len(textToSign):
            p1 = P1_LAST
        else:
            p1 = P1_MORE
        p2 = 0x00
        apdu = chr(CLA) + chr(INS_SIGN) + chr(p1) + chr(p2) + chr(len(chunk)) + bytes(chunk)
        signature = exchange(apdu)
        offset += len(chunk)
    print "Signature: " + str(signature).encode('hex')
    try:
	    signatureDeserialized = pk.ecdsa_deserialize(bytes(signature))
	    print "Deserialized Signature: " + str(signatureDeserialized)
	    print "Verified " + str(pk.ecdsa_verify(bytes(textToSign), signatureDeserialized,raw=True))
    except:   print "Can't verify. Retrieve public key first."
    return signature

## Parse bip44 path, convert to binary representation [len][int][int][int]...
def bip44tobin(path):
    path=path[2:]
    elements = path.split('/')
    result=""
    result = result + struct.pack('>B', len(elements))
    for pathElement in elements:
	element = pathElement.split('\'')
	if len(element) == 1:
		result = result + struct.pack("<I", int(element[0]))
	else:
		result = result + struct.pack("<I", 0x80000000 | int(element[0]))
    return result

class MyTCPHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        global log
        global logseq, logtop
        global version
        global pk
        # self.request is the TCP socket connected to the client
        self.data = self.rfile.readline().strip()
        print "[I] {} Received command:".format(self.client_address[0])
        print "[I] data: " + str(self.data)
        out = {}
        out["errorcode"] = -2
        logseq = 1
        logtop = 1
        try:
            cmd = json.loads(self.data)
            # return version
            if cmd["command"] == "version":
                out["version"] = version
                out["errorcode"] = 0
            #elif "version" not in cmd:
            #    print cmd 
            #    out["errorcode"] = -4
            #    out["error"] = "You should provide 'version' field."
            #elif cmd["version"] != version:
            #    out["errorcode"] = -666
            else:
                # sign bytes
                if cmd["command"] == "sign":
                    #sign message
                    sign_bytes=sign(binascii.unhexlify(cmd["message"]),bip44tobin(cmd["keyId"]))
                    #generate log entry
                    logentry = {}
                    logentry["lastLogHash"] = "TODO"
                    logentry["logseq"] = "%d" % logseq
                    logentry["timestamp"] = "%d" % int(time.time()) # get timestamp
                    logentry["tick"] = 0
                    logseq += 1
                    #add log
                    log.append(logentry)

                    # Decode from DER
                    # Fourth byte has got the length of R, and R follows
                    # (First three bytes are: 30 - sequence follows, total length byte, 02 indicating
                    # number follows)
                    r_len = int(binascii.hexlify(sign_bytes[3:4]), 16)
                    rbytes = sign_bytes[4:4+r_len]
                    # Second byte after R has got the length of S, and S follows
                    # (first byte after R has got type of value that follows - 02 - number)
                    s_len = int(binascii.hexlify(sign_bytes[5+r_len:6+r_len]), 16)
                    sbytes = sign_bytes[6+r_len:6+r_len+s_len]

                    signature = {}
                    signature["r"]=binascii.hexlify(rbytes)
                    signature["s"]=binascii.hexlify(sbytes)

                    out["signature"] = signature
                    out["errorcode"] = 0
                # retrieve log
                if cmd["command"] == "getLog":
                    if logtop >= logseq:
                        out["errorcode"] = -3
                    else:
                        logentry = log[logtop]
                        out["lastBlockHast"] = logentry["lastBlockHash"]
                        out["lastLogHash"] = logentry["lastLogHash"]
                        out["logseq"] = "%d" % logseq
                        out["timestamp"] = logentry["timestamp"]
                        out["tick"] = logentry["tick"]
                        out["errorcode"] = 0
                        logtop += 1
                # return public key
                if cmd["command"] == "getPubKey":
                    publicKey = sendCommand(INS_GET_PUBLIC_KEY,data=bip44tobin(cmd["keyId"]))
                    # verify public key
                    pk = PublicKey(bytes(publicKey), raw=True)
                    # output value
                    out["pubKey"] = binascii.hexlify(publicKey)
                    out["errorcode"] = 0
        except Exception, e:
            print('[E] Error: ' + str(e))
            #print repr(e)
            print >> sys.stderr, traceback.format_exc()
            out["error"] = 'unhandled exception with message ' + str(e)
            out["errorcode"] = -4
        self.request.sendall(json.dumps(out) + "\n")

if __name__ == "__main__":
    global key
    global log
    global logseq, logtop
    global dongle
   
    log=[]
    logseq=0
    logtop=0

    # options parsing
    parser = OptionParser()
    parser.add_option("-p","--port",dest="PORT",help="Listening port (default 9999)",default=9999)
    parser.add_option("-b","--bind",dest="HOST",help="IP to bind to. (default localhost)",default="localhost")
    (options, args) = parser.parse_args()

    HOST=options.HOST
    PORT=int(options.PORT)


    print "[I] Connecting to dongle..."
    dongle = getDongle(True)
    dongle.debug=True
    print "[I] Connected to %s" % repr(dongle)

    result=sendCommand(RSK_IS_ONBOARD)
    if ord(result[1])==1:
    	  print "[I] Dongle report is onboard..."
    else:
    	  print "[I] Dongle report is NOT onboard..."
    result=sendCommand(RSK_MODE_CMD)
    print "[I] Emulator report mode %d..." % ord(result[1])
    
    # Create the server, binding to HOST:PORT
    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    print "[I] Listening on %s:%d" % (HOST, PORT)
    server.serve_forever()
