import numpy as np
from math import log, gcd
import random
import sys
# Use sympy for polynomial operations
from sympy import Poly, symbols, GF, invert



def checkPrime(P):
    """
    Check if the input integer P is prime, if prime return True
    else return False.
    """
    if (P<=1):
        # These values are never prime
        return False
    elif (P==2 or P==3):
        # The lowest easy primes to check for
        return True
    else:
        # Otherwise check if P is divisable by any value over 4 and under P/2
        for i in range(4,P//2):
            if (P%i==0):
                # P is divisable so it is not prime
                return False

    # If we have got this far then P is not divisable by any required number, therefore prime!
    return True



def poly_inv(poly_in,poly_I,poly_mod):
    """
    Find the inverse of the polynomial poly_in in the Galois filed GF(poly_mod)
    i.e. the inverse in
        Z/poly_mod[X]/poly_I

    Inputs and outputs are given as an array of coefficients where
        x^4 + 5x^2 + 3 == [1,0,5,0,3]

    Returns
    =======
    Either an empty array if the inverse cannot be found, or the inverse of the
    polynomial poly_in as an array of coefficients.

    References
    ==========
    https://arxiv.org/abs/1311.1779
    """
    x = symbols('x')
    Ppoly_I = Poly(poly_I,x)
    Npoly_I = len(Ppoly_I.all_coeffs())
    if checkPrime(poly_mod):
        # For prime poly_mod we only need use the sympy invert routine, we then pull out
        # all the coefficients for the inverse and return (not all_coeffs() also includes
        # zeros in the array
        try:
            inv = invert(Poly(poly_in,x).as_expr(),Ppoly_I.as_expr(),domain=GF(poly_mod,symmetric=False))
        except:
            return np.array([])
    elif log(poly_mod, 2).is_integer():
        try:
            # Follow the procedure outlined in https://arxiv.org/abs/1311.1779 to find the inverse
            inv = invert(Poly(poly_in,x).as_expr(),Ppoly_I.as_expr(),domain=GF(2,symmetric=False))
            ex = int(log(poly_mod,2))
            for a in range(1,ex):
                inv = ((2*Poly(inv,x)-Poly(poly_in,x)*Poly(inv,x)**2)%Ppoly_I).trunc(poly_mod)
            inv = Poly(inv,domain=GF(poly_mod,symmetric=False))
        except:
            return np.array([])
    else:
        # Otherwise we cannot find the inverse
        return np.array([])

    # If we have got this far we have calculated an inverse, double check the inverse via poly mult
    tmpCheck = np.array(Poly((Poly(inv,x)*Poly(poly_in,x))%Ppoly_I,\
                             domain=GF(poly_mod,symmetric=False)).all_coeffs(),dtype=int)
    if len(tmpCheck)>1 or tmpCheck[0]!=1:
        sys.exit("ERROR : Error in caclualtion of polynomial inverse")

    # Passed the error check so return polynomial coefficients as array
    return padArr(np.array(Poly(inv,x).all_coeffs(),dtype=int),Npoly_I-1)

    
def padArr(A_in,A_out_size):
    """
    Take an input numpy integer array A_in and pad with leading zeros.
    Return the numy array of size A_out_size with leading zeros
    """
    return np.pad(A_in,(A_out_size-len(A_in),0),constant_values=(0))


def genRand10(L,P,M):
    """
    Generate a numpy array of length L with P 1's, M -1's and the remaining elements 0.
    The elements will be in a random order, with randomisation done using np.random.shuffle.
    This is used to generate the f, p and r arrays for NTRU encryption based on [1].

    INPUTS:
    =======
    L : Integer, the length of the desired output array.
    P : Integer, the number of `positive' i.e. +1's in the array.
    M : Integer, the number of `negative' i.e. -1's in the array.

    RETURNS:
    ========
    An integer numpy array with P +1's, M -1's and L-P-M 0's.

    REFERENCES:
    ===========
    [1] Hoffstein J, Pipher J, Silverman JH. NTRU: A Ring-Based Public Key Cryptosystem. 
        Algorithmic Number Theory. 1998; 267--288. 
    """

    # Error check, the munber of 1's and -1's must be less than or equal to length
    if P+M>L:
        sys.exit("ERROR: Asking for P+M>L.")

    # Generate an `empty' array of zeros
    R = np.zeros((L,),dtype=int)
    
    # Loop through and populate the array with 1's and -1's, not in random order
    for i in range(L):
        if i<P:
            R[i] = 1
        elif i<P+M:
            R[i] = -1
        else:
            break

    # Return a randomised array
    np.random.shuffle(R)
    return R
        
    

class NTRUDecrypt:

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
        else:
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


    def readPub(self,filename="key"):
        """
        Read a public key file
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


    def writePriv(self,filename="key"):
        """
        Write the private key file
        """
        privHead = "p ::: " + str(self.p) + "\nq ::: " + str(self.q) + "\nN ::: " \
            + str(self.N) + "\ndf ::: " + str(self.df) + "\ndg ::: " + str(self.dg) \
            + "\nd ::: " + str(self.dr) + "\nf/fp/fq/g :::"
        np.savetxt(filename+".priv", (self.f,self.fp,self.fq,self.g), header=privHead, newline="\n", fmt="%s")


    def readPriv(self,filename="key"):
        """
        Read a public key file
        """
        with open(filename+".priv","r") as f:
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

        
    def genPubPriv(self):
        """
        Generate the public and private keys from class N, p and q values.
        Also write output files for the public and private keys.
        """
        self.genfg()
        self.genh()
        self.writePub()
        self.writePriv()


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
        


class NTRUEncrypt:
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






