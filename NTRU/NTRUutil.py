import numpy as np
from math import log, gcd
import random
import sys
# Use sympy for polynomial operations
from sympy import Poly, symbols, GF, invert

np.set_printoptions(threshold=sys.maxsize)

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


def arr2str(ar):
    """
    Convert a numpy array to a string containing only the elements of the array.

    INPUTS:
    =======
    ar : Numpy array, elements will be concatonated and returned as string.

    RETURNS:
    ========
    A string containing all the elements of ar concatanated, each element seperated by a space
    """
    st = np.array_str(ar)
    st = st.replace("[", "",1)
    st = st.replace("]", "",1)
    st = st.replace("\n", "")
    st = st.replace("     ", " ")
    st = st.replace("    ", " ")
    st = st.replace("   ", " ")
    st = st.replace("  ", " ")
    return st
    

def str2bit(st):
    """
    Convert the input string st into a binary representation of the string, with each
    bit as an element of an integer numpy array.

    INPUTS:
    =======
    st : String, to be converted to an array of integers representing the string in binary.

    RETURNS:
    ========
    A numpy array containing only 1's and 0's representing the input string st in binary.
    NOTE : The initial "0b" is removed from the output array.
    """
    return np.array(list(bin(int.from_bytes(str(st).encode(),"big")))[2:],dtype=int)



def bit2str(bi):
    """
    Convert an array of bits to the string described by those bits.

    INPUTS:
    =======
    bi : Numpy integer array, containing only 1's and 0's. When flattened this represents a
         string (not including the "0b" prefix).

    RETURNS:
    ========
    A string, the binary values in the bi array converted to a string.
    """

    # Make sure the number of bits in the string is divisable by 8 (8 bits per character)
    S = padArr(bi,len(bi)+np.mod(len(bi),8))
    
    # Convert the input binary array to a string and remove any spaces
    S = arr2str(bi)
    S = S.replace(" ", "")

    # Then take each 8 bit section on its own, starting from last bits (to avoid issues
    # that can arrise from padding the front of the array with 0's)
    charOut = ""
    for i in range(len(S)//8):
        if i==0:
            charb = S[len(S)-8:]
        else:
            charb = S[-(i+1)*8:-i*8]
        charb   = int(charb,2)
        charOut = charb.to_bytes((charb.bit_length()+7)//8,"big").decode("utf-8",errors="ignore") + charOut
    return charOut


