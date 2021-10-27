import numpy as np
from NTRU.NTRUencrypt import NTRUencrypt
from NTRU.NTRUdecrypt import NTRUdecrypt
from NTRU.NTRUutil import *

import argparse



# Add the input arguments (with defaults)
parser = argparse.ArgumentParser(description="An implementation of the NTRU encryption algorithm in python3.")
parser.add_argument("-G","--Gen",action='store_true',\
                    help="Generate the public and private key files.")
parser.add_argument("-N","--N",default=503,type=int,\
                    help="The order of the polynomial ring, default 503.")
parser.add_argument("-p","--p",default=3,type=int,\
                    help="The smallest inverse polynomial modulus, default 3.")
parser.add_argument("-q","--q",default=256,type=int,\
                    help="The largest inverse polynomial modulus, default 256.")
parser.add_argument("-df","--df",default=61,type=int,\
                    help="Polynomial f has df 1's and df-1 -1's, default 61.")
parser.add_argument("-dg","--dg",default=20,type=int,\
                    help="Polynomial g has dg 1's and -1's, default 20.")
parser.add_argument("-d","--d",default=18,type=int,\
                    help="Random obfuscating polynomial has dg 1's and -1's, default 18.")
args = parser.parse_args()



if __name__ == "__main__":

    # Run all of the various NTRU methods from the command line
    
    if (args.Gen):
        # Generate the public and private key files
        N1 = NTRUdecrypt()
        N1.setNpq(N=args.N,p=args.p,q=args.q,df=args.df,dg=args.dg,d=args.d)
        N1.genPubPriv()

