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

        # Variables to save any possible encrypted messages (if req)
        self.Me = None # The encrypted message as a string
        

    def readPub(self,filename="key.pub"):
        """
        Read a public key file, generate a new r value based on new N
        """
        with open(filename,"r") as f:
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
        if m is not None:
            if len(m)>self.N:
                sys.exit("\n\nERROR: Polynomial message of degree >= N")
            self.m = m
        x = symbols('x')
        # Actually perfrom the encryption, set the class variable
        self.e = np.array(((((Poly(self.r,x)*Poly(self.h,x)).trunc(self.q)) \
                            + Poly(self.m,x))%Poly(self.I,x)).trunc(self.q).all_coeffs(), dtype=int )
        self.e = padArr(self.e,self.N)
        

    def encryptString(self,M):
        """
        Encrypt the input string M by first converting to binary

        NOTE : The public key must have been read before running this routine
        """

        # We have to have read the public key before starting
        if self.readKey == False:
            sys.exit("Error : Not read the public key file, so cannot encrypt")
        
        # Create a binary array of the input string, and pad it with leading zeros
        # such that its length is a multiple of N
        bM = str2bit(M)
        bM = padArr(bM,len(bM)-np.mod(len(bM),self.N)+self.N)
        
        # We then need an empty string to save the encrypted message to
        self.Me = ""

        # And loop through encrypting each message block (of length N) with different random polynomial
        for E in range(len(bM)//self.N):
            self.genr()                               # Gen random obsfocating polynomial
            self.setM(bM[E*self.N:(E+1)*self.N])      # Set the messsage to encrypt as single block
            self.encrypt()                            # Encrypt the saved message
            self.Me = self.Me + arr2str(self.e) + " " # Append encrypted to string

        
