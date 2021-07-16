# Code by Roark Menezes
# For UNSW COMP4337 DIMY Protocol Assignment
from ecdsa import ECDH, SigningKey, SECP128r1 # curve for 128 bit ECDH key output
from Crypto.Protocol.SecretSharing import Shamir # Shamir Secret Sharing splitting object
import threading
from binascii import hexlify
from array import *
import hashlib
import requests
import time
import socket # For UDP
import sys
import pickle
import numpy as np
import base64
import json
from bitarray import bitarray

# Global variables
global Eph_ID # Ephemeral ID
global recieverShares
global sendPort
global checkInfection

k = 3 # k value for shamir secret sharing
n = 6 # n value for shamir secret sharing
Eph_ID = -1
url_QBF = "http://ec2-3-26-37-172.ap-southeast-2.compute.amazonaws.com:9000/comp4337/qbf/query"
url_CBF = "http://ec2-3-26-37-172.ap-southeast-2.compute.amazonaws.com:9000/comp4337/cbf/upload"

def check10Min():
    global DBFno
    global DBFs
    # 7. Every 10 mins roll over the storing DB indexer
    deleteDBF = 0
    while True:
        time.sleep(120)
        DBFno = DBFno + 1
        if(DBFno != 6):
            DBFs[DBFno][:800000] = 0
        print("---------DBF Rolled Over And Emptied.---------")

def rSoc(portNum):
    # -- GLOBAL/LOCAL VARIABLES --
    i = 0
    k = 3 # hard coded k, n shamir secret sharing values. When i = 3, try
    # to build the secret
    global Eph_ID
    global ecdh
    global DBFno
    global DBFs
    global CBFupload
    global checkInfection
    recieverShares = []

    # -- Set up UDP --
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", portNum))
    s.setblocking(0)
    print("recieving data on port", portNum)
    # store 6 DBFs, DBF age, compared with current time
    DBFs = np.zeros((6, 800000))
    deleteDBF = 0
    DBFno = 0
    CBFupload = 0 # We haven't uploaded the CBF yet
    checkInfection = 0
    # Constantly read in data from the recieve port
    while True:
        try:
            #Receive up to 1024 bytes of data
            data,addr = s.recvfrom(1024)

            print("========================")
            print("Data recieved!!!: ")
            # use pickle to deserialize the advertisment
            data = pickle.loads(data)
            # ** data0 = idx, data1 = share data2 = ephID hash **
            print(data)
            #Show recieving and keeping track of shares
            i = i + 1
            print("Shares recieved = ", i)
            print("Share is: ", data[1])
            # Shares sent in order so can just use idx as i
            recieverShares.append((data[0], data[1]))
            print("share no. = %d, k = %d" % (data[0], k))
            print("!!!!!Current writing into DBF: ", DBFno, "!!!!!")
            # If we haven't been diagnosed and we have got 6 new DBFs
            # i.e. 60 minutes have passed
            if DBFno == 6:
                DBFno = 0
                if CBFupload == 0:
                    # 8. Combine all the DBFs into a QBF using simple OR
                    QBF1 = np.logical_or(DBFs[0], DBFs[1], DBFs[2])
                    QBF2 = np.logical_or(DBFs[3], DBFs[4], DBFs[5])
                    QBF = np.logical_or(QBF1, QBF2)
                    print("========= 1 HOUR IS UP! SENDING QBF TO BACKEND ==========")
                    # send QBF request on a separate thread (so data doesnt pile up
                    # at the UDP port)
                    print(np.where([QBF == 1])[1])
                    queryBFThread = threading.Thread(target=sendBloomFilter, args=(QBF, url_QBF, 'QBF',))
                    queryBFThread.start()
            # 4. if number of shares recieved = 3, attempt reconstruction
            if i >= k:
                i = 0
                key = Shamir.combine(recieverShares)
                hash = hashlib.sha1(key)
                print("key hash =", hash.hexdigest())
                print("eph hash =", data[2])
                # If we haven't built the right key, output to command line
                if(hash.hexdigest() != data[2]):
                    print("Need more shares...")
                else:
                    print("Key successfully built from 3 shares!")
                    # 5. At this point, we have our EphID (Eph_ID) and also client2's EphID(key)
                    # We can proceed with Diffie Hellman Key Exchance to build the Enc_ID
                    # We need to return the compression constant before computing EncID
                    keyOld = key
                    print(key, len(key))
                    key = bytes([2])
                    key += keyOld
                    print(key, len(key))
                    # load the public key into ecdh as bytes and then generate
                    # the shared secret (Encounter ID)
                    ecdh.load_received_public_key_bytes(key)
                    Enc_ID = ecdh.generate_sharedsecret_bytes()
                    print("ENCOUNTER ID FOUND!: ", Enc_ID)

                    # 6. Encode the Enc_ID into a DBF and then delete the EncID
                    # ** We use md5, sha1 and sha256 % 800000 to get the BF indexes **
                    idx1 = int(hashlib.sha1(Enc_ID).hexdigest(), 16) % 800000
                    idx2 = int(hashlib.sha3_256(Enc_ID).hexdigest(), 16) % 800000
                    idx3 = int(hashlib.md5(Enc_ID).hexdigest(), 16) % 800000
                    DBFs[DBFno, [idx1, idx2, idx3]] = 1
                    # Print indexes that have value 1 in the DBF we just appended
                    print(np.where([DBFs[DBFno] == 1])[1])
                    # then free Enc_ID
                    del(Enc_ID)

                # Successful or not, reset the recieved shares list to allow for
                # capturing of new advertisments
                recieverShares = []
                # Some time after CBF uploaded, check if we get a match (just for testing purposes)
                if checkInfection == 1:
                    print("*****=====***** STARTING QBF MATCH CHECK (SIMULATING QUERY) *****=====*****")
                    queryBFThread = threading.Thread(target=sendBloomFilter, args=(QBF, url_QBF, 'QBF',))
                    queryBFThread.start()
                    checkInfection = 0 # Run only once
        except socket.error:
            #If no data is received, you get here, but it's not an error
            #Ignore and continue
            pass
        time.sleep(.1)

# Function for sending QBF/CBF to backed
def sendBloomFilter(BF, url, arg):
    # BF = QBF or CBF, url = url_CBF or url_QBF, arg = 'QBF' or 'CBF'
    # 9. Send the QBF to the backend server
    # Connect to APIs
    print(np.where([BF == 1])[1])
    nums = ["%d" % x for x in BF] # convert each element to a string
    nums = "".join(nums) # join the strings to make 1 binary string

    # Convert the binary string to a bit bitarray
    bitarr = bitarray()
    for i in nums:
        bitarr.append(int(i))
    bytes = bitarr.tobytes()

    # encode the string in base64, then decode with ascii to get a string literal
    base64EncodedStr = base64.b64encode(bytes).decode('ascii')
    print(sys.getsizeof(base64EncodedStr))
    # send this off to check
    APIreq = requests.post(url, json={arg: base64EncodedStr})
    print("*** RESPONSE RECIEVED FROM BACKEND API: ", APIreq.json())

def generateEphID():
    global Eph_ID
    global sendPort
    global ecdh
    # Set up UDP socket for sending data to 127.0.0.1:8000
    tSoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tSoc.setblocking(0)

    # 1. GENERATE EPHEMERAL ID
    # Generate the 16 byte Ephemeral ID
    threading.Timer(60, generateEphID).start()
    ecdh = ECDH(curve=SECP128r1)
    ecdh.generate_private_key()

    # Compression adds a constant (0x02) to start of key
    Eph_ID = ecdh.get_public_key().to_string("compressed")
    print(Eph_ID)
    # Remove compression constant
    Eph_ID = Eph_ID[1:17]
    print(len(Eph_ID))

    # 2. SHAMIR SECRET SHARING
    # Split EphID into 6 parts, transmit one every 10 seconds
    print("EphID = ", Eph_ID)
    # Calculate hash of entire ID
    hash = hashlib.sha1(Eph_ID)
    print(hash.hexdigest())
    # Split ID
    senderShares = Shamir.split(3, 6, Eph_ID)
    advertisment = []

    # 3. Broadcast n shares @ 1 unique share per 10 seconds
    for idx, share in senderShares:
        print("Index #%d: %s" % (idx, hexlify(share)))
        advertisment.append(idx)
        advertisment.append(share)
        advertisment.append(hash.hexdigest())
        # use pickle to serialize the advertisment
        msg = pickle.dumps(advertisment)
        tSoc.sendto(msg, ("127.0.0.1",sendPort))
        advertisment = []
        print("Sent data to port", sendPort)
        time.sleep(10)

# Function for simulating when positively diagnosed user sends CBF to backend
def simulateCovid():
    global CBFupload
    global DBFs
    # Simulate positive covid diagnoses after 30 sec (upload CBF)
    time.sleep(740)
    CBF1 = np.logical_or(DBFs[0], DBFs[1], DBFs[2])
    CBF2 = np.logical_or(DBFs[3], DBFs[4], DBFs[5])
    CBF = np.logical_or(CBF1, CBF2)
    CBFupload = 1
    print("%%%%%%%%%%%%%%% Uploading CBF, QBF generation will now stop %%%%%%%%%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%% Uploading CBF, QBF generation will now stop %%%%%%%%%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%% Uploading CBF, QBF generation will now stop %%%%%%%%%%%%%%%%%%%%%%")
    print("%%%%%%%%%%%%%%% Uploading CBF, QBF generation will now stop %%%%%%%%%%%%%%%%%%%%%%")
    sendBloomFilter(CBF, url_CBF, 'CBF')

def checkInfectionVal():
    global checkInfection
    time.sleep(760)
    checkInfection = 1
# Command Line Arg checks
if len(sys.argv) != 3:
    raise ValueError('Please provide send/recieve port number for this clients UDP communication.')
else:
    recievePort = int(sys.argv[1])
    sendPort = int(sys.argv[2])

# Start thread for recieving UDP data on 127.0.0.1:8000
UDPthread = threading.Thread(target=rSoc,args=(recievePort,))
UDPthread.start()

# Rollover DBFs every 10 mins
check10Thread = threading.Thread(target=check10Min)
check10Thread.start()

# Simulate positively diagnosed user
simCovThread = threading.Thread(target=simulateCovid)
simCovThread.start()

checkInfectionThread = threading.Thread(target=checkInfectionVal)
checkInfectionThread.start()
# Generate ephemeral ID (new one every 60 seconds)
generateEphID()
