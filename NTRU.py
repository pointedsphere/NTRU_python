
# We use numpy for all our polynomial operations
import numpy as np
# And math for a few bits and pieces
import math
import sys


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

            

class NTRUDecrypt:

    """
    A class to decrypt data with the NTRU method.

    This class can also generate the private key used for decryption (which can be saved to
    an external file) and the public key used for encryption (which can also be saved to an
    external file).
    """


    
    def __init__(self, N=503, p=3, q=256):
        """
        Initialise with some default N, p and q parameters
        """
        self.N = N # Public N
        self.p = p # Public p
        self.q = q # Public q

        self.f  = np.zeros((self.N-1,), dtype=int) # Private polynomial f
        self.fp = np.zeros((self.N-1,), dtype=int) # Inverse of f mod p
        self.fq = np.zeros((self.N-1,), dtype=int) # Inverse of f mod q
        self.g  = np.zeros((self.N-1,), dtype=int) # Private polynomial g
        self.h  = np.zeros((self.N-1,), dtype=int) # Public key polynomial (mod q)

        
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
            self.f  = np.zeros((self.N-1,), dtype=int)
            self.fp = np.zeros((self.N-1,), dtype=int)
            self.fq = np.zeros((self.N-1,), dtype=int)
            self.g  = np.zeros((self.N-1,), dtype=int)
            self.h  = np.zeros((self.N-1,), dtype=int)

        # First check that q is less than p
        if (p_in>q_in):
            sys.exit("\n\nERROR: Input q is less than p\n\n")
        else:
            if (math.gcd(p_in,q_in)!=1):
                sys.exit("\n\nERROR: Input p and q are not coprime\n\n")
            else:
                self.p = p_in
                self.q = q_in
        
