# NTRUEncrypt_python

An implementation of the NTRU encryption and decryption algorithm in Python 3 following the original paper by Hoffstein, Pipher and Silverman [1].

This package is in **very** active development. As such in it's current state should be approached more cautiously than one usually would approach a cryptosystem implementation.

## Notes

Polynomial operations are currently carried out using the `sympy` module. Though we can be confident in the results produced using `sympy` it is not cost optimal, especially for large polynomials. Later development will use more sophisticated methods to reduce cost, for example using Fast Fourier Transforms to carry out the polynomial multiplication.

## References

[1] Hoffstein J, Pipher J, Silverman JH. NTRU: A Ring-Based Public Key Cryptosystem. In: International Algorithmic Number Theory Symposium. Springer; 1998. p. 267--288. 
