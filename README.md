7trXMk6Z's Useful Functions, Classes, and Variables
==================

A complete re-write of my now deprecated "main_functions" repository.

Useful functions and variables and classes, mostly of my own design.

Pretty much completely stable, except for the SimpleBitcoinTx() class, which still needs some work and re-writing and optimization.  Note that it is still definitely not professional level code, and I frequently use hexstrs as opposed to raw bytes.  (So you'll see teh results of len() and similar functions be double what you might expect.)

This will likely be used in future projects I write.

Aside from the standard library, it needs: ecdsa, pycrypto, scrypt, and my own pyBIP0038

There is no setup.py because this isn't intended for distribution.  It's intended for my own personal use.