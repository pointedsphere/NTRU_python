import numpy as np
from math import log, gcd
import sys
from sympy import Poly, symbols
from NTRU.NTRUutil import *

class NTRUdecrypt:

    """
    A class to decrypt data with the NTRU method.

    This class can also generate the private key used for decryption (which can be saved to
    an external file) and the public key used for encryption (which can also be saved to an
    external file).
    """


    def __init__(self, N=503, p=3, q=256, df=61, dg=20, d=18):
        """
        Initialise with some default N, p and q parameters (if not given as initialisation params)
        
        INPUTS:
        =======
        N  : Integer, order of the polynomial ring.
        p  : Integer, modulus of inverse of f polynomial for fp.
        q  : Integer, modulus of inverse of f polynomial for fq.
        df : Integer, number of coefficients 1 in polynomial f.
        dg : Integer, number of coefficients 1 in polynomial g.
        gr : Integer, number of coefficients 1 in the random polynomial (used in encryption).
        """
        self.N = N # Public N
        self.p = p # Public p
        self.q = q # Public q

        self.df = df # Number of 1's in f
        self.dg = dg # Number of 1's in g
        self.dr = d # Number of 1's in r (for encryption)
        
        self.f  = np.zeros((self.N,), dtype=int) # Private polynomial f
        self.fp = np.zeros((self.N,), dtype=int) # Inverse of f mod p
        self.fq = np.zeros((self.N,), dtype=int) # Inverse of f mod q
        self.g  = np.zeros((self.N,), dtype=int) # Private polynomial g
        self.h  = np.zeros((self.N,), dtype=int) # Public key polynomial (mod q)

        # Ideal as array representing polynomial
        self.I         = np.zeros((self.N+1,), dtype=int)
        self.I[self.N] = -1
        self.I[0]      = 1

        # Empty string to store a decrypted string
        self.M = None


    def setNpq(self,N=None,p=None,q=None,df=None,dg=None,d=None):
        """
        Set the N, p and q values and perform checks on their validity, i.e.:
          - N must be prime
          - q is greater than p
          - p and q are coprime

        Note : The class variables N, p and q are not private, specifically as (for experimentaion)
               a user may want to set these values to unwise paremeters.

        REFERENCES:
        ===========
        [1] Hoffstein J, Pipher J, Silverman JH. NTRU: A Ring-Based Public Key Cryptosystem. 
            Algorithmic Number Theory. 1998; 267--288. 
        """
        
        if N is not None:
            # First check N is prime
            if (not checkPrime(N)):
                sys.exit("\n\nERROR: Input value of N not prime\n\n")
            else:
                # Error checks based on number of desired 1's and -1's in df, dg and dr arrays
                if df is None:
                    if 2*self.df>N:
                        sys.exit("\n\nERROR: Input N too small compared to default df "+str(self.df)+"\n\n")
                if dg is None:
                    if 2*self.dg>N:
                        sys.exit("\n\nERROR: Input N too small compared to default dg "+str(self.dg)+"\n\n")
                if d is None:
                    if 2*self.dr>N:
                        sys.exit("\n\nERROR: Input N too small compared to default dr "+str(self.dr)+"\n\n")
                # Otherwise set N, and initialise polynomial arrays
                self.N  = N
                self.f  = np.zeros((self.N,), dtype=int)
                self.fp = np.zeros((self.N,), dtype=int)
                self.fq = np.zeros((self.N,), dtype=int)
                self.g  = np.zeros((self.N,), dtype=int)
                self.h  = np.zeros((self.N,), dtype=int)
                self.I         = np.zeros((self.N+1,), dtype=int)
                self.I[self.N] = -1
                self.I[0]      = 1

        # Can only set p and q together
        if (p is None and q is not None) or (p is not None and q is None):
            sys.exit("\n\nError: Can only set p and q together, not individually")
        elif (p is not None) and (q is not None):
            # First check that 8p<=q from [1]
            if ((8*p)>q):
                sys.exit("\n\nERROR: We require 8p <= q\n\n")
            else:
                if (gcd(p,q)!=1):
                    sys.exit("\n\nERROR: Input p and q are not coprime\n\n")
                else:
                    self.p = p
                    self.q = q

        if df is not None:
            if 2*df>self.N:
                sys.exit("\n\nERROR: Input df such that 2*df>N\n\n")
            else:
                self.df = df

        if dg is not None:
            if 2*dg>self.N:
                sys.exit("\n\nERROR: Input dg such that 2*dg>N\n\n")
            else:
                self.dg = dg
                
        if d is not None:
            if 2*d>self.N:
                sys.exit("\n\nERROR: Input dr such that 2*dr>N\n\n")
            else:
                self.dr = d
                    

    def invf(self):
        """
        Invert the f polynomial with respect to input p and q values (class values).
        Return True if inverses w.r.t. p and q exists (after setting self.fp and self.fq)
        Return False if inverse w.r.t. either/or p/q does nto exist
        """
        fp_tmp = poly_inv(self.f,self.I,self.p)
        fq_tmp = poly_inv(self.f,self.I,self.q)
        if len(fp_tmp)>0 and len(fq_tmp)>0:
            self.fp = np.array(fp_tmp)
            self.fq = np.array(fq_tmp)
            # Make sure the arrays have leading zeros
            if len(self.fp)<self.N:
                self.fp = np.concatenate([np.zeros(self.N-len(self.fp),dtype=int),self.fp])
            if len(self.fq)<self.N:
                self.fq = np.concatenate([np.zeros(self.N-len(self.fq),dtype=int),self.fq])            
            return True
        else:
            return False

                
    def genfg(self):
        """
        Randomly generate f and g for the private key and their inverses
        """
        # Make 100 attempts and exit with error if we cant find an inverse in there
        maxTries = 100
        # We don't need g to be invertable, so just randomly gen
        self.g = genRand10(self.N,self.dg,self.dg)
        # Now try and generate an f with inverses mod p and mod q
        for i in range(maxTries):
            self.f = genRand10(self.N,self.df,self.df-1)
            invStat = self.invf()
            if invStat==True:
                break
            elif i==maxTries-1:
                sys.exit("Cannot generate required inverses of f")


    def genh(self):
        """
        Generate the public key from the class values (that must have been generated previously)
        """
        x = symbols('x')
        self.h = Poly((Poly(self.p*self.fq,x).trunc(self.q)*Poly(self.g,x)).trunc(self.q)\
                      %Poly(self.I,x)).all_coeffs()


    def writePub(self,filename="key"):
        """
        Write the public key file
        """
        pubHead = "p ::: " + str(self.p) + "\nq ::: " + str(self.q) + "\nN ::: " + str(self.N) \
             + "\nd ::: " + str(self.dr) + "\nh :::"
        np.savetxt(filename+".pub", self.h, newline=" ", header=pubHead, fmt="%s")


    def readPub(self,filename="key.pub"):
        """
        Read a public key file
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


    def writePriv(self,filename="key"):
        """
        Write the private key file
        """
        privHead = "p ::: " + str(self.p) + "\nq ::: " + str(self.q) + "\nN ::: " \
            + str(self.N) + "\ndf ::: " + str(self.df) + "\ndg ::: " + str(self.dg) \
            + "\nd ::: " + str(self.dr) + "\nf/fp/fq/g :::"
        np.savetxt(filename+".priv", (self.f,self.fp,self.fq,self.g), header=privHead, newline="\n", fmt="%s")


    def readPriv(self,filename="key.priv"):
        """
        Read a public key file
        """
        with open(filename,"r") as f:
            self.p  = int(f.readline().split(" ")[-1])
            self.q  = int(f.readline().split(" ")[-1])
            self.N  = int(f.readline().split(" ")[-1])
            self.df = int(f.readline().split(" ")[-1])
            self.dg = int(f.readline().split(" ")[-1])
            self.dr = int(f.readline().split(" ")[-1])
            tmp = f.readline()
            self.f  = np.array(f.readline().split(" "),dtype=int)
            self.fp = np.array(f.readline().split(" "),dtype=int)
            self.fq = np.array(f.readline().split(" "),dtype=int)
            self.g  = np.array(f.readline().split(" "),dtype=int)
        self.I         = np.zeros((self.N+1,), dtype=int)
        self.I[self.N] = -1
        self.I[0]      = 1

        
    def genPubPriv(self,keyfileName="key"):
        """
        Generate the public and private keys from class N, p and q values.
        Also write output files for the public and private keys.
        """
        self.genfg()
        self.genh()
        self.writePub(keyfileName)
        self.writePriv(keyfileName)


    def decrypt(self,e):
        """
        Decrypt the message given as in an input array e into the decrypted message m and return.
        """
        # The encrypted message e must have degree < N
        if len(e)>self.N:
            sys.exit("Encrypted message has degree > N")
        # Error checks passed, now decrypt and return as a np array
        x = symbols('x')
        a = ((Poly(self.f,x)*Poly(e,x))%Poly(self.I,x)).trunc(self.q)
        b = a.trunc(self.p)
        c = ((Poly(self.fp,x)*b)%Poly(self.I,x)).trunc(self.p)

        return np.array(c.all_coeffs(),dtype=int)


    def decryptString(self,E):
        """
        Decrypt a message encoded using the requisite public key from an encoded to a decoded string.
        """

        # First convert the string to a numpy
        Me = np.fromstring(E, dtype=int, sep=' ')
        # And check the input array is the correct length, i.e. an integer multiple of N
        if np.mod(len(Me),self.N)!=0:
            sys.exit("\n\nERROR : Input decrypt string is not integer multiple of N\n\n")

        # Now decrypt each block, appending to the message string
        Marr = np.array([],dtype=int)
        for D in range(len(Me)//self.N):
            Marr = np.concatenate((Marr,padArr(self.decrypt(Me[D*self.N:(D+1)*self.N]),self.N)))

        # And return the string decrypted
        self.M = bit2str(Marr)
    
