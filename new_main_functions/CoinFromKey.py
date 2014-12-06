#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ec_math import *
from hexlify_permissive import *
from hash_funcs import *
from base58_hex_conversions import *
from bitcoin_funcs import *
from misc_funcs_and_vars import *

class CoinFromKey(object):
    """
    Input a key and version byte in order to have a single object for a bitcoin address.

    If object creation input key is public key, you get the following variable attributes:
    self.pubkeyU  # Uncompressed 04 public key
    self.pubkeyC  # Compressed 02/03 public key
    self.pubkey   # Either pubkeyU or pubkeyC depending on preferCompressed bool
    self.versionbyte # version byte for use in converting public key to address
    self.addressU  # Address for uncompressed public key
    self.addressC  # Address for compressed public key
    self.address   # Either addressU or addressC depending on preferCompressed bool

    If object creation input key is private key, you get the following additional variable attributes:
    self.privkey  # 64-char hex private key
    self.privversionbyte # Private key version byte, which is self.versionbyte added to 0x80, except for namecoin.
    self.privkeyWIFu  # Base58 encoded private key with version byte and no trailing 01 since it's uncompressed
    self.privkeyWIFc  # Base58 encoded private key with version byte with trailing 01 since it is compressed
    self.privkeyWIF   # self.privkeyWIFu or self.privkeyWIFc depending on preferCompressed bool

    Additionally, after object creation, you can invoke the method
    self.encrypt("password")
    which will BIP0038 encrypt the private key (or throw an exception if only the pubkey is known)
    and give you the following additional object variables:
    self.encryptedU
    self.encryptedC
    self.encrypted

    There is no decrypt function since in order to encrypt in the first place, you need the private key.
    There is also no function to add a private key to the object after it has been created with a public key, since you can just create a new object and destroy the old one.

    __str__ of the object displays the public address (which depends on the preferCompressed bool)

    >>> doctester = CoinFromKey('d52039b991f3fde9440616a3c246fd800064edd42c6c4d43f778b5d6208dee1b')
    >>> str(doctester)
    '17rovkBWSvTRBHHNPxVGKuHCR1ryEaTnwX'
    >>> doctester.encrypted
    ''
    >>> doctester.privkey
    'd52039b991f3fde9440616a3c246fd800064edd42c6c4d43f778b5d6208dee1b'
    >>> doctester.privkeyWIF
    'L4MzwPcLfV7jQKPbTKFHHUW83V9MxvKNfBovR9Rs4hLhPJSEAoMp'
    >>> doctester.pubkeyU
    '040d24dc2289ce808851686e9df06ce03ba80e8aef9ac58e52b9aba96893633b8d833c3356f2cfa61d30b221a0fae073b940697be95a91ba59531fa8e449a5ad62'
    >>> doctester.encrypt("satoshi")
    '6PYMYpJ5K7u7XVe8AXiqWGtNKCyMZEfsBked21zYtThZqeBKCH2aXdbgQM'
    >>> doctester.encrypted
    '6PYMYpJ5K7u7XVe8AXiqWGtNKCyMZEfsBked21zYtThZqeBKCH2aXdbgQM'
    """

    def __init__(self, keyinput, pubversionbyte='00', preferCompressed=True):
        super(CoinFromKey,self).__init__()
        try:
            self.test1 = binascii.unhexlify(keyinput)
            self.test1 = ""
            self.keyinput = str(keyinput)
            assert len(self.keyinput) == 64 or len(self.keyinput) == 66 or len(self.keyinput) == 130
        except:
            raise TypeError("First input must be a hexstr public or private key of 64, 66, or 130 chars in length.")
        try:
            self.test1 = binascii.unhexlify(pubversionbyte)
            self.test1 = ""
            self.versionbyte = str(pubversionbyte)
            assert len(pubversionbyte) == 2
            assert int(pubversionbyte,16) < int('80',16) and int(pubversionbyte,16) > -1
        except:
            raise TypeError("Second input must be a 2-char hex version byte for the public key of the coin type")
        self.preferCompressed = preferCompressed
        if self.versionbyte == '34':
            self.privversionbyte = '80' # Namecoin pirvkey version byte is 0x80
        else:
            self.privversionbyte = hexlify_(int(self.versionbyte,16) + int('80',16),2)
        assert len(self.privversionbyte) == 2
        self.encrypted = str("")
        self.privkey = str("")
        self.privkeyWIFu = str("")
        self.privkeyWIFc = str("")
        if len(self.keyinput) == 64:
            self.privkey = self.keyinput
            self.privkeyWIFu = base58_check_and_encode(str(self.privversionbyte) + str(self.keyinput))
            self.privkeyWIFc = base58_check_and_encode(str(self.privversionbyte) + str(self.keyinput) + str('01'))
            self.pubkeyU = privkey_to_pubkey(self.privkey,False)
            self.pubkeyC = privkey_to_pubkey(self.privkey,True)
        elif len(self.keyinput) == 66:
            self.pubkeyU = uncompress_pubkey(self.keyinput)
            self.pubkeyC = self.keyinput
        elif len(self.keyinput) == 130:
            self.pubkeyU = str(self.keyinput)
            self.pubkeyC = compress_pub_key(self.keyinput)
        self.addressU = pubkey_to_address(self.pubkeyU,self.versionbyte)
        self.addressC = pubkey_to_address(self.pubkeyC,self.versionbyte)
        if self.preferCompressed:
            self.pubkey = str(self.pubkeyC)
            self.address = str(self.addressC)
            if self.privkey:
                self.privkeyWIF = str(self.privkeyWIFc)
        else:
            self.pubkey = str(self.pubkeyU)
            self.address = str(self.addressU)
            if self.privkey:
                self.privkeyWIF = str(self.privkeyWIFu)

    def encrypt(self, password):
        if not self.privkey:
            raise Exception("Key object only has public part, cannot encrypt")
        self.password = str(password)
        if int(sys.version_info.major) == 2:
            self.password = unicode(self.password)
        self.password = unicodedata.normalize('NFC',self.password)
        self.password = str(self.password)
        from pyBIP0038 import encrypt_privkey_from_password
        self.encryptedU = encrypt_privkey_from_password(self.password, self.privkey, False)
        self.encryptedC = encrypt_privkey_from_password(self.password, self.privkey, True)
        self.password = ""
        self.hexenckey = base58_decode(self.encryptedU,False,False)
        self.newflagbyte = hexlify_(int(self.hexenckey[4:6],16) + int('20',16),2)
        assert len(self.newflagbyte) == 2
        # self.encryptedC = base58_check_and_encode(str(self.hexenckey[:4]) + str(self.newflagbyte) + str(self.hexenckey[6:]))
        self.hexenckey, self.newflagbyte = "",""
        if self.preferCompressed:
            self.encrypted = str(self.encryptedC)
        else:
            self.encrypted = str(self.encryptedU)
        return str(self.encrypted)

    def __str__(self):
        if self.preferCompressed:
            return self.addressC
        else:
            return self.addressU

if __name__ == "__main__":
    import doctest
    doctest.testmod()
