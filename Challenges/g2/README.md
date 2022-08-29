# AES128 for VE475 Challenge 2

Author:  Shiroakki 

**Kindly hint: If you're looking through my codes to find inspiration about g2, then here it is: DONT USE BLOCK CIPHER TO PROCEED. (updated 29/08/22)**



### Compilation 

You can directly run `make`  to compile and execute the program. In case of `Makefile` failure, please run `g++ -o g2 main.cpp -static` instead.



### Command Line Arguments

- `--generate` to generate random pair of keys
- `--encrypt 'YourPlaintext' [--key '/keyfilepath']`
- `--decrypt 'Ciphertext' [--key 'keyfilepath']`



### I/O specifications

- The complete alphabet: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.;?!()`, a total of 69 characters.

- You can either use `hex` or `alphabet` representation for both `plaintext` and `ciphertext` input

- As for key, it should be a 16-bit long representation of alphabet characters. 

- Only ciphertext with length that is a multiple of **32** will be accepted. 

  

