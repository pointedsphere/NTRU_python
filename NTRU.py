import numpy as np

from NTRU.NTRUencrypt import NTRUencrypt
from NTRU.NTRUdecrypt import NTRUdecrypt

    
# Testing

# Initialise the private and public keys, write them out (and test reading)
N1 = NTRUdecrypt()
N1.setNpq(N=503,p=3,q=256,df=216,dg=72,d=55)
N1.genPubPriv()
N1.readPriv()

# Encrypt a test mesage array
N2 = NTRUencrypt()
N2.readPub()
N2.setM([1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,1,-1,0,0,0,0,0,1,-1])
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



