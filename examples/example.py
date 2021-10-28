import numpy as np
import sys
sys.path.append("../")

from NTRU.NTRUencrypt import NTRUencrypt
from NTRU.NTRUdecrypt import NTRUdecrypt
from NTRU.NTRUutil import *

# Testing

# Initialise the private and public keys, write them out (and test reading)
N1 = NTRUdecrypt()
N1.setNpq(N=107,p=3,q=64,df=15,dg=12,d=5)
N1.genPubPriv()

# Encrypt a test mesage array
N2 = NTRUencrypt()
N2.readPub()
N2.setM([1,-1,0,0,0,0,0,1,-1])
N2.encrypt()

# Print out some interesting values
print("N : ",N1.N,N2.N)
print("p : ",N1.p,N2.p)
print("q : ",N1.q,N2.q)
print("m : ",N2.m)
print("r : ",N2.r)
print("e : ",N2.e)

# Test the decryption
print("d : ",N1.decrypt(N2.e))

# Now try encrypting a string
MSG = """

SCENE I. _On a ship at sea: a tempestuous noise of thunder
and lightning heard.

"""
print("Mb : ",str2bit(MSG))
N2.encryptString(MSG)
print("Me : ",N2.Me)

# And then decrypt the string and print for a check
N1.decryptString(N2.Me)
print("M  : ",N1.M)
