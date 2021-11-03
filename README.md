# NTRU in python

An implementation of the NTRU encryption and decryption algorithm in Python 3 following the original paper by Hoffstein, Pipher and Silverman [1].

This package is a toy implementation created in order to understand the cryptosystem better. As such in its current state it should be approached with more caution than one would usually use when approaching a cryptosystem implementation found on github.

Furthermore, polynomials are carried out using the `sympy` module, which is not necessarily the most cost effective method for polynomial operations especially for larger order polynomial rings.

Also, note the encrypted outputs are not compressed in any way. There are trivial methods one could use to do this, but it is easier to see exactly what is going on with the algorithm without any form of compression. As such data here is left uncompressed (for now).



## General Usage (from command line)

Before use the python modules `sympy` and `numpy` must be installed to the environment (via `pip` or similar).



### Generating Keys

To generate the keys we call `NTRY.py` with the flag `-G`. This can be done with 3 default levels of security based on the parameters given in [1] using the flags

- `-M`  ::: Moderate security with N=107, p=3, q=64, df=15, dg=12, d=5
- `-H`  ::: High security with N=167, p=3, q=128, df=61, dg=20, d=18.
- `-HH` ::: Highest security with N=256, p=3, q=128, df=216, dg=72, d=55.

where N is the order of the polynomial ring, p is the modulus of the polynomial f (which has df 1 coefficients and df-1 -1 coefficients), q is the modulus of the polynomial g (which has dg 1 and -1 coefficients) and d is the number of 1 and -1 coefficients in the obfuscating polynomial.

Values of N, p, q, df, dg and d can also be given individually with the flags `-N`, `-p`, `-q`, `-df`, `-dg` and `-d` respectively.

We may also change the filenames of the output key files with the flag `-k` (the default is `key`).

#### Example

To generate the public and private keys of high security with the key file name "NTRU_key" we use the command

```
python3 NTRU.py -G -M -k NTRU_key
```

which generates 2 files in the current directory, `NTRU_key.pub` and `NTRU_key.priv` (which can be found in the examples directory).



### Encryption of a String

We can encrypt either a string given on the command line with the flag `-eS`, or read text from a file and encrypt with the flag `-eF`. We output the encrypted data either to the command line with the flag `-T` or to a file with the flag `-O`.

The key can be given (just filename, no `.pub`) with the flag `-k`, if not given default of `key` is assumed.

Note, if the string has a length greater than the maximum order of a polynomial in the current ring (N) it is split into blocks of length N. Each block is encrypted with a different random obfuscating polynomial of order N with d 1 and -1 coefficients.

#### Example

We utilise the public key `NTRU_key.pub` we generated earlier for this encryption. First we encrypt the string "Hello World" and output the result to the command line:

```
python3 NTRU.py -k NTRU_key -eS "Hello World" -T
```

which returns the encrypted data to the command line:

```
8 28 -21 19 -29 -25 -8 -20 -24 19 12 -16 18 -4 -15 -28 -23 -20 31 31 -13 7 9 21 -2 4 25 -20 -14 -30 13 3 1 -10 -9 27 -20 -13 5 -31 -13 15 3 -22 13 -2 21 -19 -27 20 -31 25 -14 -3 3 -15 -11 18 -22 -1 -31 -3 -7 21 20 19 -25 -11 25 24 32 -21 -14 -10 19 -15 -26 17 -12 -17 8 -5 24 14 17 -18 15 18 -26 -25 12 -12 -27 24 17 -19 -12 -31 -18 -19 26 24 -3 0 -28 26 -4
```

Note the command line string input must be within quotation marks.

We then take a text file containing Act 1 Scene 1 of The Tempest (`A1S1_Tempest` in the examples directory) and encrypt that, saving the output to the file `enc.dat` (also in examples directory). This is done with the command:

```
python3 NTRU.py -k NTRU_key -eF A1S1_Tempest -O enc.dat
```



### Decryption of a String

Decryption of a string is done in a similar way, using an input string on the command line with the flag `-dS` or with an input file using the `-dF` flag. We output the encrypted data either to the command line with the flag `-T` or to a file with the flag `-O`.

The key can be given (just filename, no `.priv`) with the flag `-k`, if not given default of `key` is assumed.

#### Example

Here we use the key and encrypted data from the previous examples. First to decrypt the message "Hello World" we call

```
python3 NTRU.py -k NTRU_key -T -dS "8 28 -21 19 -29 -25 -8 -20 -24 19 12 -16 18 -4 -15 -28 -23 -20 31 31 -13 7 9 21 -2 4 25 -20 -14 -30 13 3 1 -10 -9 27 -20 -13 5 -31 -13 15 3 -22 13 -2 21 -19 -27 20 -31 25 -14 -3 3 -15 -11 18 -22 -1 -31 -3 -7 21 20 19 -25 -11 25 24 32 -21 -14 -10 19 -15 -26 17 -12 -17 8 -5 24 14 17 -18 15 18 -26 -25 12 -12 -27 24 17 -19 -12 -31 -18 -19 26 24 -3 0 -28 26 -4"
```

which outputs "Hello World" to the command line.

To decrypt the file `enc.dat` we call

```
python3 NTRU.py -k NTRU_key -dF enc.dat -O decoded.dat
```

which returns Act 1 Scene 1 of The Tempest as the file `decoded.dat` (see examples directory).



## References

[1] Hoffstein J, Pipher J, Silverman JH. NTRU: A Ring-Based Public Key Cryptosystem. In: International Algorithmic Number Theory Symposium. Springer; 1998. p. 267--288. 
