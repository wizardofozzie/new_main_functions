#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Relative import off for doctests
# from ec_math import *
# from hexlify_permissive import *
# from hash_funcs import *
# from base58_hex_conversions import *
# from bitcoin_funcs import *
# from misc_funcs_and_vars import *
# from CoinFromKey import *
# from Bip32Key import *
# from BIP39 import *

from .ec_math import *
from .hexlify_permissive import *
from .hash_funcs import *
from .base58_hex_conversions import *
from .bitcoin_funcs import *
from .misc_funcs_and_vars import *
from .CoinFromKey import *
from .Bip32Key import *
from .BIP39 import *

class ElectrumV2EngSeed(object):
    """
    Much code taken from:
    https://github.com/spesmilo/electrum/blob/master/lib/mnemonic.py

    TODO: Doctest

    TODO: Double check that this is the correct format.  When Electrum V2 comes out, verify this with what it tells you.
    """

    SEED_BIP44 = "01"
    SEED_2FA = "101"

    def __init__(self,input=128,password=str(""),prefix=SEED_BIP44,custom_entropy=1):
        if 'int' in str(type(input)) or 'long' in str(type(input)):
            assert input >= 32
            self.hex = self.generate_new_seed(input,prefix,custom_entropy)
        else:
            try:
                self.hex = hexlify_(binascii.unhexlify(input))
            except:
                try:
                    self.hex = ElectrumV2EngSeed.wordlist_to_hex(input)
                except:
                    raise Exception("Input must be an integer for number of bits for new random seed, or hex, hexstr, or a str list of lowercase words, each separated by a single space.")
        try:
            assert ElectrumV2EngSeed.is_valid_seed(ElectrumV2EngSeed.hex_to_wordlist(self.hex),prefix)
        except:
            raise Exception("Input seed is not a valid Electrum v2 seed.  Prefix check failed.")
        self.words = ElectrumV2EngSeed.hex_to_wordlist(self.hex)
        self.prefix = prefix
        self.custom_entropy = custom_entropy
        self.password = password
        self.bip32seed = ElectrumV2EngSeed.Bip32Seed(self.words,self.password)

    def generate_new_seed(self, numbits=128, prefix=SEED_BIP44, custom_entropy=1):
        from math import ceil, log
        n = int(ceil(log(custom_entropy,2)))
        k = len(prefix)*4
        n_added = int(max(16, k + numbits - n))
        numbytes = int(ceil(n_added/8.0))
        while True:
            my_entropy = int(hexlify_(os.urandom(numbytes)),16)
            if my_entropy < 2**n_added:
                break
        nonce = 0
        while True:
            nonce += 1
            i = hexlify_(int(custom_entropy * (my_entropy + nonce)))
            words = ElectrumV2EngSeed.hex_to_wordlist(i)
            assert i == ElectrumV2EngSeed.wordlist_to_hex(words)
            if ElectrumV2EngSeed.is_valid_seed(words, prefix):
                break
        assert ElectrumV2EngSeed.check_words_with_entropy_int(words,custom_entropy,prefix)
        assert ElectrumV2EngSeed.is_valid_seed(words,prefix)
        return i

    @staticmethod
    def is_valid_seed(words, prefix=SEED_BIP44):
        prefix = str(prefix)
        try:
            words = words.lower()
            words = str(words)
            i = ElectrumV2EngSeed.wordlist_to_hex(words)
        except:
            raise Exception("Wordlist input is not valid. Words must be lowercase with a single space inbetween")
        else:
            i = None
        sha512out = hexlify_(hmac.new(binascii.unhexlify(binascii.hexlify(bytearray("Seed version",'utf-8'))),binascii.unhexlify(binascii.hexlify(bytearray(words,'utf-8'))), hashlib.sha512).digest())
        return sha512out.startswith(prefix)

    @staticmethod
    def check_words_with_entropy_int(seed, custom_entropy=1, prefix=SEED_BIP44):
        assert ElectrumV2EngSeed.is_valid_seed(seed,prefix)
        i = int(ElectrumV2EngSeed.wordlist_to_hex(seed),16)
        return i % custom_entropy == 0

    @staticmethod
    def hex_to_wordlist(i):
        try:
            i = int(hexlify_(binascii.unhexlify(i)),16)
        except:
            raise Exception("Input must be hex seed.")
        n = len(Bip39EngClass.BIP0039_ENG_WORDLIST)
        words = []
        while i:
            x = i%n
            i = i/n
            words.append(Bip39EngClass.BIP0039_ENG_WORDLIST[x])
        return str(' '.join(words))

    @staticmethod
    def wordlist_to_hex(seed):
        seed = str(seed)
        n = len(Bip39EngClass.BIP0039_ENG_WORDLIST)
        words = seed.split()
        i = 0
        while words:
            w = words.pop()
            k = Bip39EngClass.BIP0039_ENG_WORDLIST.index(w)
            i = i*n + k
        return hexlify_(int(i))

    @staticmethod
    def Bip32Seed(words,password=""):
        from pbkdf2 import PBKDF2 as kdf_
        try:
            words = words.lower()
            words = str(words)
            i = ElectrumV2EngSeed.wordlist_to_hex(words)
        except:
            raise Exception("Input must be lowercase list of words, each separated by a space.")
        else:
            i = None
        password = str(password)
        presalt = 'mnemonic'
        if int(sys.version_info.major) == 2:
            words = unicode(words)
            password = unicode(password)
            presalt = unicode(presalt)
        words = unicodedata.normalize('NFC',words)
        if "  " in words:
            words = str(words).replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        words = str(words)
        password = unicodedata.normalize('NFC',password)
        presalt = unicodedata.normalize('NFC',presalt)
        salt = str(presalt) + str(password)
        output = kdf_(words,salt,2048,macmodule=hmac,digestmodule=hashlib.sha512).read(64)
        bip32seed = hexlify_(output)
        assert len(bip32seed) == 128
        return bip32seed

if __name__ == "__main__":
    import doctest
    doctest.testmod()
