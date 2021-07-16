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
import math
import base64
import json
from bitarray import bitarray, util
DBF = np.zeros((6, 800000))
DBF[1, [2, 3, 5]] = 1
DBF[0, [3, 5, 7]] = 1

# id = b'\xd7\x9ce\xf8\x8c\xd8|\x0c}j\xe5\x84\xb6\x93\xb7)'
# idx1 = int(hashlib.sha1(b'\xd7\x9ce\xf8\x8c\xd8|\x0c}j\xe5\x84\xb6\x93\xb7)').hexdigest(), 16) % 10
# print(idx1)
url_QBF = "http://ec2-3-26-37-172.ap-southeast-2.compute.amazonaws.com:9000/comp4337/qbf/query"
url_CBF = "http://ec2-3-26-37-172.ap-southeast-2.compute.amazonaws.com:9000/comp4337/cbf/upload"

#print(np.where([DBF[1] == 1])[1])
#print(type(DBF[1]))
QBF1 = np.logical_or(DBF[0], DBF[1], DBF[2])
QBF2 = np.logical_or(DBF[3], DBF[4], DBF[5])
QBF = np.logical_or(QBF1, QBF2)
print(np.where([QBF == 1])[1])
nums = ["%d" % x for x in QBF] # convert each element to a string
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
# QBF_API = requests.post(url_QBF, json={'QBF': base64EncodedStr})
# print(QBF_API.json())
