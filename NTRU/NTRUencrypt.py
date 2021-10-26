import numpy as np
import sys
from sympy import Poly, symbols
from NTRU.NTRUutil import *

class NTRUencrypt:
    """
    A class to encrypt some data based on a known public key.
    """

    
    def __init__(self, N=503, p=3, q=256, d=18):
        """
        Initialise with some default N, p and q parameters.
        """
        self.N = N # Public N
        self.p = p # Public p
        self.q = q # Public q

        self.dr = d # Number of 1's in r (for encryption)
        
        self.g = np.zeros((self.N,), dtype=int) # Private polynomial g
        self.h = np.zeros((self.N,), dtype=int) # Public key polynomial (mod q)
        self.r = np.zeros((self.N,), dtype=int) # A random `blinding value'
        self.genr()
        self.m = np.zeros((self.N,), dtype=int) # The message array
        self.e = np.zeros((self.N,), dtype=int) # The encrypted message
        
        # Ideal as array representing polynomial
        self.I         = np.zeros((self.N+1,), dtype=int)
        self.I[self.N] = -1
        self.I[0]      = 1

        self.readKey = False # We have not yet read the public key file


    def readPub(self,filename="key"):
        """
        Read a public key file, generate a new r value based on new N
        """
        with open(filename+".pub","r") as f:
            self.p  = int(f.readline().split(" ")[-1])
            self.q  = int(f.readline().split(" ")[-1])
            self.N  = int(f.readline().split(" ")[-1])
            self.dr = int(f.readline().split(" ")[-1])
            self.h  = np.array(f.readline().split(" ")[3:-1],dtype=int)
        self.I         = np.zeros((self.N+1,), dtype=int)
        self.I[self.N] = -1
        self.I[0]      = 1
        self.genr()
        self.readKey = True


    def genr(self):
        """
        Generate the random binding polynomial array r, with values mod q
        """
        self.r = genRand10(self.N,self.dr,self.dr)
        

    def setM(self,M):
        """
        Set the class message M after performing error checks.
        Before calling this the public key values must have been set (i.e. read)
        NOTE : Message M must be an array describing polynomial coefficients, where the
               polynomial must be degree < N.
        NOTE : The coeffcients must be in [-p/2,p/2].
        NOTE : Message array must be an integer array.
        """
        if self.readKey==False:
            sys.exit("ERROR : Public key not read before setting message")
        if len(M)>self.N:
            sys.exit("ERROR : Message length longer than degree of polynomial ring ideal")
        for i in range(len(M)):
            if M[i]<-self.p/2 or M[i]>self.p/2:
                sys.exit("ERROR : Elements of message must be in [-p/2,p/2]")
        # Passed the error checks, so now save the class message function, inc leading zeros
        self.m = padArr(M,self.N)

            
    def encrypt(self,m=None):
        """
        Encrypt the message m into the array e
        NOTE : The message m must be set before this routine is called
        """
        # We have to have read the public key before starting
        if self.readKey == False:
            sys.exit("Error : Not read the public key file, so cannot encrypt")
        # If message not set as input then set from the class variable
        if m is None:
            m = self.m
        x = symbols('x')
        self.e = np.array(((((Poly(self.r,x)*Poly(self.h,x)).trunc(self.q)) \
                            + Poly(self.m,x))%Poly(self.I,x)).trunc(self.q).all_coeffs(), dtype=int )

