
# We use numpy for all our polynomial operations
import numpy as np
# And math for a few bits and pieces
from math import log, gcd
import random
import sys

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
    if checkPrime(poly_mod):
        # For prime poly_mod we only need use the sympy invert routine, we then pull out
        # all the coefficients for the inverse and return (not all_coeffs() also includes
        # zeros in the array
        try:
            inv = invert(Poly(poly_in,x).as_expr(),Poly(poly_I,x).as_expr(),domain=GF(poly_mod,symmetric=False))
        except:
            return np.array([])
        return np.array(Poly(inv,x).all_coeffs(),dtype=int)
    elif log(poly_mod, 2).is_integer():
        try:
            # Follow the procedure outlined in https://arxiv.org/abs/1311.1779 to find the inverse
            inv = invert(Poly(poly_in,x).as_expr(),Poly(poly_I,x).as_expr(),domain=GF(2,symmetric=False))
            ex = int(log(poly_mod,2))
            for a in range(1,ex):
                inv = ((2*Poly(inv,x)-Poly(poly_in,x)*Poly(inv,x)**2)%Poly(poly_I,x)).trunc(poly_mod)
            inv = Poly(inv,domain=GF(poly_mod,symmetric=False))
        except:
            return np.array([])
        return np.array(inv.all_coeffs(),dtype=int)
    else:
        # Otherwise we cannot find the inverse
        return np.array([])



class NTRUDecrypt:

    """
    A class to decrypt data with the NTRU method.

    This class can also generate the private key used for decryption (which can be saved to
    an external file) and the public key used for encryption (which can also be saved to an
    external file).
    """


    def __init__(self, N=503, p=3, q=256):
        """
        Initialise with some default N, p and q parameters.
        """
        self.N = N # Public N
        self.p = p # Public p
        self.q = q # Public q

        self.f  = np.zeros((self.N,), dtype=int) # Private polynomial f
        self.fp = np.zeros((self.N,), dtype=int) # Inverse of f mod p
        self.fq = np.zeros((self.N,), dtype=int) # Inverse of f mod q
        self.g  = np.zeros((self.N,), dtype=int) # Private polynomial g
        self.h  = np.zeros((self.N,), dtype=int) # Public key polynomial (mod q)

        # Ideal as array representing polynomial
        self.I         = np.zeros((self.N+1,), dtype=int)
        self.I[self.N] = -1
        self.I[0]      = 1


    def setNpq(self,N_in,p_in,q_in):
        """
        Set the N, p and q values and perform checks on their validity, i.e.:
          - N must be prime
          - q is greater than p
          - p and q are coprime

        Note : The class variables N, p and q are not private, specifically as (for experimentaion)
               a user may want to set these values to unwise paremeters.
        """

        # First check N is prime
        if (not checkPrime(N_in)):
            sys.exit("\n\nERROR: Input value of N not prime\n\n")
        else:
            # Otherwise set N, and initialise polynomial arrays
            self.N = N_in
            self.f  = np.zeros((self.N,), dtype=int)
            self.fp = np.zeros((self.N,), dtype=int)
            self.fq = np.zeros((self.N,), dtype=int)
            self.g  = np.zeros((self.N,), dtype=int)
            self.h  = np.zeros((self.N,), dtype=int)
            self.I         = np.zeros((self.N+1,), dtype=int)
            self.I[self.N] = -1
            self.I[0]      = 1

        # First check that q is less than p
        if (p_in>q_in):
            sys.exit("\n\nERROR: Input q is less than p\n\n")
        else:
            if (gcd(p_in,q_in)!=1):
                sys.exit("\n\nERROR: Input p and q are not coprime\n\n")
            else:
                self.p = p_in
                self.q = q_in


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
        for i in range(maxTries):
            for j in range(self.N):
                self.f[j] = random.randint(-1,1)
            invStat = self.invf()
            if invStat==True:
                break
            elif i==maxTries-1:
                sys.exit("Cannot generate required inverses of f")
        for j in range(self.N):
            self.g[j] = random.randint(-1,1)


    def genh(self):
        """
        Generate the public key from the class values (that must have been generated previously)
        """
        x = symbols('x')
        self.h = Poly(Poly(self.p*self.fq,x)*Poly(self.g,x)%Poly(self.I,x),domain=GF(self.q,symmetric=False)).all_coeffs()


    def writePub(self,filename="key"):
        """
        Write the public key file
        """
        pubHead = "p ::: " + str(self.p) + "\nq ::: " + str(self.q) + "\nN ::: " \
            + str(self.N) + "\nh :::"
        np.savetxt(filename+".pub", self.h, newline=" ", header=pubHead, fmt="%s")


    def readPub(self,filename="key"):
        """
        Read a public key file
        """
        with open(filename+".pub","r") as f:
            self.p = int(f.readline().split(" ")[-1])
            self.q = int(f.readline().split(" ")[-1])
            self.N = int(f.readline().split(" ")[-1])
            self.h = np.array(f.readline().split(" ")[3:-1],dtype=int)
        

    def writePriv(self,filename="key"):
        """
        Write the private key file
        """
        privHead = "p ::: " + str(self.p) + "\nq ::: " + str(self.q) + "\nN ::: " \
            + str(self.N) + "\nf/fp/fq/g :::"
        np.savetxt(filename+".priv", (self.f,self.fp,self.fq,self.g), header=privHead, newline="\n", fmt="%s")


    def readPriv(self,filename="key"):
        """
        Read a public key file
        """
        with open(filename+".priv","r") as f:
            self.p = int(f.readline().split(" ")[-1])
            self.q = int(f.readline().split(" ")[-1])
            self.N = int(f.readline().split(" ")[-1])
            tmp = f.readline()
            self.f  = np.array(f.readline().split(" "),dtype=int)
            self.fp = np.array(f.readline().split(" "),dtype=int)
            self.fq = np.array(f.readline().split(" "),dtype=int)
            self.g  = np.array(f.readline().split(" "),dtype=int)
        
        
    def genPubPriv(self):
        """
        Generate the public and private keys from class N, p and q values.
        Also write output files for the public and private keys
        """
        self.genfg()
        self.genh()
        self.writePub()
        self.writePriv()
    
        
