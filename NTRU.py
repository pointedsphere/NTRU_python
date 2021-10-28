import numpy as np
from NTRU.NTRUencrypt import NTRUencrypt
from NTRU.NTRUdecrypt import NTRUdecrypt
from NTRU.NTRUutil import *

import argparse
from argparse import RawTextHelpFormatter

import sys
from os.path import exists


prog_description = """

An implementation of the NTRU encryption algorithm in python3.

Based on the original NTRU paper by Hoffstein, Pipher and Silverman [1].

"""

prog_epilog="""

References:
[1] Hoffstein J, Pipher J, Silverman JH. NTRU: A Ring-Based Public Key Cryptosystem. In: International Algorithmic Number Theory Symposium. Springer; 1998. p. 267--288.

"""


# Add the input arguments
parser = argparse.ArgumentParser(prog="NTRU Encrypt/Decrypt",\
                                 description=prog_description,\
                                 epilog=prog_epilog,\
                                 formatter_class=RawTextHelpFormatter)
parser.add_argument("-k","--key-name",default="key",type=str,\
                    help="The filename of the public and private keys (key_name.pub and (key_name.priv).")
parser.add_argument("-G","--Gen",action="store_true",\
                    help="Generate the public and private key files.\n"\
                    +"Default key parameters are the high security parameters from [1].")
parser.add_argument("-M","--moderate_sec",action="store_true",\
                    help="If given with -G flag generate moderate security keys from [1] with N=107, p=3, q=64.")
parser.add_argument("-H","--high-sec",action="store_true",\
                    help="If given with -G flag generate high security keys from [1] with N=167, p=3, q=128.")
parser.add_argument("-HH","--highest-sec",action="store_true",\
                    help="If given with -G flag generate highest security keys from [1] with N=503, p=3, q=256.")
parser.add_argument("-N","--N",default=167,type=int,\
                    help="The order of the polynomial ring, default 503.")
parser.add_argument("-p","--p",default=3,type=int,\
                    help="The smallest inverse polynomial modulus, default 3.")
parser.add_argument("-q","--q",default=128,type=int,\
                    help="The largest inverse polynomial modulus, default 256.")
parser.add_argument("-df","--df",default=61,type=int,\
                    help="Polynomial f has df 1's and df -1's, default 61.")
parser.add_argument("-dg","--dg",default=20,type=int,\
                    help="Polynomial g has dg 1's and -1's, default 20.")
parser.add_argument("-d","--d",default=18,type=int,\
                    help="Random obfuscating polynomial has d 1's and -1's, default 18.")
parser.add_argument("-O","--out_file",type=str,\
                    help="Output file for encrypted/decrypted data/string.")
parser.add_argument("-T","--out_in_term",action="store_true",\
                    help="Output encrypted/decrypted data/string to terminal.")
parser.add_argument("-eS","--Enc_string",type=str,\
                    help="Encrypt the string given as an input.\n"\
                    +"Note: String must be given in quotation marks, e.g. \"a string\".\n"
                    +"Note: This always requires a known public key.")
parser.add_argument("-eF","--Enc_file",type=str,\
                    help="Encrypt the string given in this input file.\n"
                    +"Note: This always requires a known public key.")
parser.add_argument("-dS","--Dec_string",type=str,\
                    help="Decrypt the string given as an input.\n"\
                    +"Note: String must be given in quotation marks, e.g. \"a string\".\n"
                    +"Note: This always requires a known private key.")
parser.add_argument("-dF","--Dec_file",type=str,\
                    help="Decrypt the string given in this input file.\n"
                    +"Note: This always requires a known private key.")
args = parser.parse_args()



if __name__ == "__main__":


    
    if (args.Gen):

        # Generate a public and private keyfile based on input flags (or lack thereof)
        
        # Initialise the class to gen the keys in
        N1 = NTRUdecrypt()

        # Set the parameters based on input flags (or lack thereof)
        if (args.moderate_sec):
            N1.setNpq(N=107,p=3,q=64,df=15,dg=12,d=5)
        elif (args.highest_sec):
            N1.setNpq(N=503,p=3,q=256,df=216,dg=72,d=55)
        else:
            N1.setNpq(N=167,p=3,q=128,df=61,dg=20,d=18)
            
        # Actually generate and save the public and private keys
        N1.genPubPriv(args.key_name)



    elif (args.Enc_string or args.Enc_file):

        # Encrypt some data using the given public key
        
        # First check if the public key file exists
        if not exists(args.key_name+".pub"):
            sys.exit("ERROR : Public key '"+args.key_name+".pub' not found.")

        # We can only have one input to encrypt
        if args.Enc_string and args.Enc_file:
            sys.exit("ERROR : More than one input to encrypt given.")
            
        # We need an output method specified
        if not args.out_file and not args.out_in_term:
            sys.exit("ERROR : At least one output method must be specified.")

        # Then initialise an encryption class
        E = NTRUencrypt()

        # And read the public key
        E.readPub(args.key_name+".pub")
        
        # Extract the data to encrypt
        if args.Enc_string:
            to_encrypt = args.Enc_string
        elif args.Enc_file:
            # Need to check if the file exists
            if not exists(args.Enc_file):
                sys.exit("ERROR : Input file '"+args.Enc_file+"' not found.")
            # If it does then read all the data from it
            with open(args.Enc_file,"r") as f:
                to_encrypt = "".join(f.readlines())

        # Then encrypt the data
        E.encryptString(to_encrypt)

        # And output the encrypted data
        if args.out_in_term:
            # Just print the encrypted data to the terminal
            print(E.Me)
        elif args.out_file:
            # Write the encrypted data to an output file
            with open(args.out_file,"w") as f:
                f.write(E.Me)



    elif (args.Dec_string or args.Dec_file):

        # Decrypt some data using the known private key

        # First check if the private key file exists
        if not exists(args.key_name+".priv"):
            sys.exit("ERROR : Public key '"+args.key_name+".priv' not found.")

        # We can only have one input to decrypt
        if args.Dec_string and args.Dec_file:
            sys.exit("ERROR : More than one input to decrypt given.")
                    
        # We need an output method specified
        if not args.out_file and not args.out_in_term:
            sys.exit("ERROR : At least one output method must be specified.")

        # Then initialise an decryption class
        D = NTRUdecrypt()

        # And read the public key
        D.readPriv(args.key_name+".priv")

        # Extract the data to decrypt
        if args.Dec_string:
            to_decrypt = args.Dec_string
        elif args.Dec_file:
            # Need to check if the file exists
            if not exists(args.Dec_file):
                sys.exit("ERROR : Input file '"+args.Dec_file+"' not found.")
            # If it does then read all the data from it
            with open(args.Dec_file,"r") as f:
                to_decrypt = "".join(f.readlines())

        # Then decrypt the string
        D.decryptString(to_decrypt)
        
        # And output the decrypted data
        if args.out_in_term:
            # Just print the encrypted data to the terminal
            print(D.M)
        elif args.out_file:
            # Write the encrypted data to an output file
            with open(args.out_file,"w") as f:
                f.write(D.M)



