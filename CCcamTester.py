#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by michask0 (michal@e-kacprzak.eu) -- https://github.com/kacprzak-michael
# Based on CLineTester by Dagger -- https://github.com/gavazquez

import sys
import argparse

### CriptoBlock

def Xor(buf):
    cccam = "CCcam"
    for i in range(0, 8):
        buf[8 + i] = 0xff & (i * buf[i])
        if i < 5:
            buf[i] ^= ord(cccam[i])
    return buf

class CryptographicBlock(object):
    def __init__(self):
        self._keytable = [0] * 256
        self._state = 0
        self._counter = 0
        self._sum = 0

    def Init(self, key, len):
        for i in range(0, 256):
            self._keytable[i] = i
        j = 0
        for i in range(0, 256):
            j = 0xff & (j + key[i % len] + self._keytable[i])
            self._keytable[i], self._keytable[j] = self._keytable[j], self._keytable[i]
        self._state = key[0]
        self._counter = 0
        self._sum = 0

    def Decrypt(self, data, len):
        for i in range(0, len):
            self._counter = 0xff & (self._counter + 1)
            self._sum = self._sum + self._keytable[self._counter]

            #Swap keytable[counter] with keytable[sum]
            self._keytable[self._counter], self._keytable[self._sum & 0xFF] = \
                self._keytable[self._sum & 0xFF], self._keytable[self._counter]

            z = data[i]
            data[i] = z ^ self._keytable[(self._keytable[self._counter] + \
                self._keytable[self._sum & 0xFF]) & 0xFF] ^ self._state
            z = data[i]
            self._state = 0xff & (self._state ^ z)

    def Encrypt(self, data, len):
        for i in range(0, len):
            self._counter = 0xff & (self._counter + 1)
            self._sum = self._sum + self._keytable[self._counter]

            #Swap keytable[counter] with keytable[sum]
            self._keytable[self._counter], self._keytable[self._sum & 0xFF] = \
                self._keytable[self._sum & 0xFF], self._keytable[self._counter]

            z = data[i]
            data[i] = z ^ self._keytable[(self._keytable[self._counter & 0xFF] + \
                self._keytable[self._sum & 0xFF]) & 0xff] ^ self._state

            self._state = 0xff & (self._state ^ z)

### CCcamTester

recvblock = CryptographicBlock()
sendblock = CryptographicBlock()

def TestCline(cline):
    import socket, re, sys, array, time, select

    returnValue = False
    regExpr = re.compile('[C]:\s*(\S+)+\s+(\d*)\s+(\S+)\s+([\w.-]+)')
    match = regExpr.search(cline)

    if match is None:
        return False;

    testSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
    testSocket.settimeout(30) #timeout of 30 seconds

    host = match.group(1)
    port = int(match.group(2))
    username = match.group(3)
    password = match.group(4)

    try:
        ip = socket.gethostbyname(host)
        testSocket.connect((ip, port))

        DoHanshake(testSocket) #Do handshake with the server

        try:
            userArray = GetPaddedUsername(username)
            sendcount = SendMessage(userArray, len(userArray), testSocket) #Send the username

            passwordArray = GetPaddedPassword(password)
            sendblock.Encrypt(passwordArray, len(passwordArray)) #We encript the password

            #But we send "CCCam" with the password encripted CriptoBlock
            cccamArray = GetCcam()
            sendcount = SendMessage(cccamArray, len(cccamArray), testSocket)

            receivedBytes = bytearray(20)
            recvCount = testSocket.recv_into(receivedBytes, 20)

            if recvCount > 0:
                recvblock.Decrypt(receivedBytes, 20)
                if (receivedBytes.decode("ascii").rstrip('\0') == "CCcam"):
                    #print "Working cline: " + cline
                    returnValue = 0
                else:
                    #print "Wrong ACK received!"
                    returnValue = 1#2
            else:
                #print "Bad username/password for cline: " + cline
                returnValue = 2

        except:
            #print "Bad username/password for cline: " + cline
            returnValue = 2
    except:
        #print "Error while connecting to cline: " + cline
        returnValue = 3#1

    testSocket.close()
    return returnValue

def GetPaddedUsername(userName):
    import array

    #We create an array of 20 bytes with the username in it as bytes and padded with 0 behind
    #Like: [23,33,64,13,0,0,0,0,0,0,0...]
    userBytes = array.array("B", userName)
    userByteArray = FillArray(bytearray(20), userBytes)

    return userByteArray

def GetCcam():
    import array

    #We create an array of 6 bytes with the "CCcam\0" in it as bytes
    cccamBytes = array.array("B", "CCcam")
    cccamByteArray = FillArray(bytearray(6), cccamBytes)
    return cccamByteArray

def GetPaddedPassword(password):
    import array

    #We create an array of with the password in it as bytes
    #Like: [23,33,64,13,48,78,45]
    passwordBytes = array.array("B", password)
    passwordByteArray = FillArray(bytearray(len(password)),passwordBytes)

    return passwordByteArray

def DoHanshake(socket):
    import hashlib, array

    random = bytearray(16)
    socket.recv_into(random, 16) #Receive first 16 "Hello" random bytes
    #print "Hello bytes: " + random

    random = Xor(random); #Do a Xor with "CCcam" string to the hello bytes

    sha1 = hashlib.sha1()
    sha1.update(random)
    sha1digest = array.array('B', sha1.digest()) #Create a sha1 hash with the xor hello bytes
    sha1hash = FillArray(bytearray(20), sha1digest)

    recvblock.Init(sha1hash, 20) #initialize the receive handler
    recvblock.Decrypt(random, 16)

    sendblock.Init(random, 16) #initialize the send handler
    sendblock.Decrypt(sha1hash, 20)

    rcount = SendMessage(sha1hash, 20, socket) #Send the a crypted sha1hash!

def SendMessage(data, len, socket):
    buffer = FillArray(bytearray(len), data)
    sendblock.Encrypt(buffer, len)
    rcount = socket.send(buffer)
    return rcount

def FillArray(array, source):
    if len(source) <= len(array):
        for i in range(0, len(source)):
            array[i] = source[i]
    else:
        for i in range(0, len(array)):
            array[i] = source[i]
    return array

### Mine

def returnMessages(exit_msg):
    if exit_msg == 0:
        EM = "Working cline"
        EC = 0
    elif exit_msg == 1:
        EM = "Wrong ACK received!"
        EC = 2
    elif exit_msg == 2:
        EM = "Bad username/password for cline"
        EC = 2
    elif exit_msg == 3:
        EM = "Error while connecting to cline"
        EC = 2
    return [EM + ": ", EC]

def parseArgs():
    parser = argparse.ArgumentParser(description='CCcam checker with exit codes for NRPE. It could be used with files or single clines.\n\
    DO NOT FORGET ABOUT QUOTATION MARKS FOR ARUMENTS!\n\
    Examples:\n\
    ./CCcamTester.py -l "C: wal.sie.korpo 12345 dziewicniema666 0123456789"\n\
    ./CCcamTester.py -f "/direct/path/cccamd.list"',
    formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-f', '--file', dest='file', help='Check C-Lines from file', default='/usr/keys/cccamd.list')
    parser.add_argument('-l', '--line', dest='line', help='Check given C-Line')

    return parser.parse_args()

if __name__ == "__main__":
    args = parseArgs()

    if args.line != None:
        check_line = TestCline(str(args.line))
        EM = returnMessages(check_line)[0] + args.line
        EC = returnMessages(check_line)[1]
        if EC == 0:
            EM = "Success!!! " + EM

        print EM
        sys.exit(EC)

    else:
        import os.path
        if os.path.isfile(args.file):

            exit_codes = []
            EM0 = str(returnMessages(0)[0])
            EM1 = str(returnMessages(1)[0])
            EM2 = str(returnMessages(2)[0])
            EM3 = str(returnMessages(3)[0])

            with open(args.file) as f:
                content = [x.strip() for x in f.readlines()]
                for cline in content:
                    if not cline.startswith("#"):
                        check_line = TestCline(str(cline))
                        if check_line == 3:
                            EM3 = EM3 + cline + "; "
                            exit_codes.append(check_line)

                        elif check_line == 2:
                            EM2 = EM2 + cline + "; "
                            exit_codes.append(check_line)

                        elif check_line == 1:
                            EM1 = EM1 + cline + "; "
                            exit_codes.append(check_line)

                        elif check_line == 0:
                            EM0 = EM0 + cline + "; "
                            exit_codes.append(check_line)

                EM = ""

                if EM3 != str(returnMessages(3)[0]):
                    EM = EM + EM3

                if EM2 != str(returnMessages(2)[0]):
                    EM = EM + EM2

                if EM1 != str(returnMessages(1)[0]):
                    EM = EM + EM1

                if EM0 != str(returnMessages(0)[0]):
                    EM = EM + EM0


                EC = returnMessages(max(exit_codes))[1]
                if EC == 0:
                    EM = "Success!!! " + EM
                print EM
                sys.exit(EC)

        else:
            print "File %s does not exist!" % args.file
            sys.exit(3)
