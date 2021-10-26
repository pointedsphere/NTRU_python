import numpy as np

from NTRU.NTRUencrypt import NTRUencrypt
from NTRU.NTRUdecrypt import NTRUdecrypt
from NTRU.NTRUutil import *

# Testing

# Initialise the private and public keys, write them out (and test reading)
N1 = NTRUdecrypt()
N1.setNpq(N=107,p=3,q=64,df=15,dg=12,d=5)
N1.genPubPriv()
N1.readPriv()
# N1.setNpq()

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

BOATSWAIN.
None that I more love than myself. You are a counsellor: if you can
command these elements to silence, and work the peace of the present,
we will not hand a rope more. Use your authority: if you cannot, give
thanks you have lived so long, and make yourself ready in your cabin
for the mischance of the hour, if it so hap.—Cheerly, good hearts!—Out
of our way, I say.

 [_Exit._]

GONZALO.
I have great comfort from this fellow. Methinks he hath no drowning
mark upon him. His complexion is perfect gallows. Stand fast, good
Fate, to his hanging! Make the rope of his destiny our cable, for our
own doth little advantage! If he be not born to be hang’d, our case is
miserable.

 [_Exeunt._]

 Re-enter Boatswain.

BOATSWAIN.
Down with the topmast! yare! lower, lower! Bring her to try wi’ th’
maincourse.

 [_A cry within._]

 A plague upon this howling! They are louder than the weather or our
 office.

"""
print("Mb : ",str2bit(MSG))
N2.encryptString(MSG)
print("Me : ",N2.Me)

# And then decrypt the string
N1.decryptString(N2.Me)
print("M  : ",N1.M)
