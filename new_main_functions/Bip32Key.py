#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ec_math import *
from hexlify_permissive import *
from hash_funcs import *
from base58_hex_conversions import *
from bitcoin_funcs import *
from misc_funcs_and_vars import *
from CoinFromKey import *
from StealthAddress import *

class Bip32Key(object):
    """
    >>> doctestkey = Bip32Key("000102030405060708090a0b0c0d0e0f")
    >>> str(doctestkey)
    'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
    >>> doctestkey.pub
    'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
    >>> doctestkey.deserialized
    '0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35'
    >>> doctestkey.privkey
    'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35'
    >>> doctestkey.child("m/0h/1/2h/2/1000000000")
    'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'
    >>> doctestkey2 = Bip32Key("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL")
    >>> doctestkey2.depth
    4
    >>> doctestkey2.index
    4294967294
    >>> doctestkey2.index_nothard
    2147483646
    >>> doctestkey2.pubkey
    '02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0'
    """

    def __init__(self,generatorinput=hexlify_(os.urandom(32),64),testnet=False,generatepubonly=False):
        """
        Generates BIP0032 master key from input.  Input can be string of hex chars
        or a bip32 key entered as a string beginning with "xprv" or "xpub".
        """
        super(Bip32Key,self).__init__()
        self.generatorinput = generatorinput
        self.testnet = testnet
        self.generatepubonly = generatepubonly
        self.isSerializedInput = False
        try:
            self.test1 = binascii.unhexlify(self.generatorinput)
            self.test2 = int(self.generatorinput,16)
            self.test1, self.test2 = None, None
        except Exception as e:
            if ('str' in str(type(self.generatorinput)) or 'unicode' in str(type(self.generatorinput))) and \
               (self.generatorinput[:4] == "xprv" or self.generatorinput[:4] == "xpub" or \
                self.generatorinput[:4] == "tprv" or self.generatorinput[:4] == "tpub"):
                if len(self.generatorinput) != 111:
                    raise TypeError("xprv/xpub key str entered is not correct length, please check for errors.")
                self.isSerializedInput = True
            else:
                raise TypeError("Input must be hex or serialized xprv/xpub key str. Input exception thrown was:  " + str(e))
        if self.generatorinput[:4] == "xpub" or self.generatorinput[:4] == "tpub":
            self.generatepubonly = True
        if self.isSerializedInput:
            try:
                self.deserialized, self.isValid = base58_decode(self.generatorinput,True,False)
            except:
                raise Exception("Unknown error attempting to base58 decode serialized key input.")
            if not self.isValid:
                raise Exception("Serialized xpub/xprv key entered had checksum match failure during base58 decoding attempt.")
            assert len(self.deserialized) == 156
            self.deserialized = str(self.deserialized)
            self.versionbytes = str(self.deserialized[:8])
            self.depthbyte = str(self.deserialized[8:10])
            self.depth = int(self.depthbyte,16)
            self.parentfpr = str(self.deserialized[10:18])
            self.indexhex = str(self.deserialized[18:26])
            self.chaincode = str(self.deserialized[26:90])
            self.index = int(self.indexhex,16)
            if self.index >= 2**31:
                self.index_nothard = self.index - 2**31
                self.isHardened = True
            else:
                self.index_nothard = self.index
                self.isHardened = False
            if self.generatorinput[:4] == "xprv" or self.generatorinput[:4] == "tprv":
                if self.deserialized[90:92] != '00':
                    raise Exception("Key input appears to be serialized private key, but 45th byte prefixing the key is not 0x00.")
                self.priv = str(self.generatorinput)
                self.privkey = str(self.deserialized[92:])
                self.pubkey = privkey_to_pubkey(self.privkey,True)
                if self.generatorinput[:4] == "xprv":
                    self.testnet = False
                    self.pub = base58_check_and_encode(str("0488b21e") + str(self.deserialized[8:90]) + str(self.pubkey))
                else:
                    self.testnet = True
                    self.pub = base58_check_and_encode(str("043587cf") + str(self.deserialized[8:90]) + str(self.pubkey))
                if self.generatepubonly:
                    self.priv = ''
                    self.privkey = ''
                    if self.versionbytes == "0488ade4":
                        self.versionbytes = str("0488b21e")
                    elif self.versionbytes == "04358394":
                        self.versionbytes = str("043587cf")
            else:
                self.priv = ''
                self.privkey = ''
                self.pubkey = str(self.deserialized[90:])
                self.pub = str(self.generatorinput)
                if self.generatorinput[:4] == "xpub":
                    self.testnet = False
                else:
                    self.testnet = True
        else:
            self.i = hexlify_(hmac.new(binascii.unhexlify(binascii.hexlify(bytearray("Bitcoin seed",'utf-8'))), 
                                       binascii.unhexlify(self.generatorinput), hashlib.sha512).digest())
            assert len(self.i) == 128
            self.privkey = str(self.i[:-64])
            self.chaincode = str(self.i[64:])
            self.i = None
            self.pubkey = privkey_to_pubkey(self.privkey,True)
            if self.generatepubonly:
                if self.testnet:
                    self.versionbytes = str("043587cf")
                else:
                    self.versionbytes = str("0488b21e")
            else:
                if self.testnet:
                    self.versionbytes = str("04358394")
                else:
                    self.versionbytes = str("0488ade4")
            self.depthbyte = str("00")
            self.depth = int(self.depthbyte,16)
            self.parentfpr = str("00000000")
            self.indexhex = str("00000000")
            self.index = int(0)
            self.index_nothard = self.index
            self.isHardened = False
            if self.generatepubonly:
                self.privkey = ''
                self.priv = ''
                self.pub = base58_check_and_encode(self.versionbytes + self.depthbyte +
                                                   self.parentfpr + self.indexhex + self.chaincode +
                                                   self.pubkey)
            else:
                if self.testnet:
                    self.pub = base58_check_and_encode(str("043587cf") + self.depthbyte +
                                                       self.parentfpr + self.indexhex + self.chaincode +
                                                       self.pubkey)
                else:
                    self.pub = base58_check_and_encode(str("0488b21e") + self.depthbyte +
                                                       self.parentfpr + self.indexhex + self.chaincode +
                                                       self.pubkey)
                self.priv = base58_check_and_encode(self.versionbytes + self.depthbyte +
                                                    self.parentfpr + self.indexhex + self.chaincode +
                                                    str("00") + self.privkey)
            self.deserialized = self.versionbytes + self.depthbyte + self.parentfpr + self.indexhex + self.chaincode
            if self.generatepubonly:
                self.deserialized = self.deserialized + self.pubkey
            else:
                self.deserialized = self.deserialized + "00" + self.privkey
        if not self.generatepubonly:
            assert len(self.priv) == 111
            assert self.priv[1:4] == "prv"
            self.masterkey = str(self.priv)
        else:
            self.masterkey = str(self.pub)
        assert len(self.pub) == 111
        assert self.pub[1:4] == "pub"
        self.generatepubonly, self.generatorinput, self.isSerializedInput = None, None, None
        self.pub = str(self.pub)
        self.priv = str(self.priv)
        self.deserialized = str(self.deserialized)

    def child(self,path="m/0",outputpub=False):
        """
        Bip32Key.CKDpath(), for self

        >>> doctestkey = Bip32Key("000102030405060708090a0b0c0d0e0f")
        >>> doctestkey.child("m/0h/1/2h/2/1000000000")
        'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'
        """

        self.path = path
        self.outputpub = outputpub
        if self.priv != '':
            self.tempoutput = Bip32Key.CKDpath(self.priv,self.path,self.outputpub)
        else:
            if not self.outputpub:
                raise Exception("Cannot output child private key from parent public key.")
            self.tempoutput =  Bip32Key.CKDpath(self.pub,self.path,self.outputpub)
        if self.outputpub and self.tempoutput[1:4] == "prv":
            self.tempoutput = Bip32Key.priv_to_pub(self.tempoutput)
        self.path, self.outputpub = None, None
        return self.tempoutput

    @staticmethod
    def Bip38Encrypt(password,serializedprivkey):
        """
        Bip38 encrypts a single xprv or tprv key.  Extends the total hex length by 4 bytes for the bip38 address hash, and re-writes the prefix bytes to be xp38 or tp38.  Whereas a normal xprv key has the last 32 bytes after the 00 be the private key, that is now replaced by 36 bytes, which comprise 4-byte-address-hash followed by 32-byte-encrypted-key.  (It's just the least significant 36 bytes of a normal 0142 Bip38 key hex.)

        ***WARNING:  This process is unique to this module.  It is not used anywhere else!!!***

        >>> Bip32Key.Bip38Encrypt("satoshi","xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        'xp38Fz45cvHGxGoybFU6Jq9JN1qkK9nENrQfPVmFi4ngcEGpmN9odFo1fTTEZWw8GKqFUpuUWBNg493MbXn2bmKpSZeKRrMcrRL5mFhJN29mPSrTCDbWd'
        """

        if ('str' not in str(type(serializedprivkey)) and 'unicode' not in str(type(serializedprivkey))) or \
           (serializedprivkey[:4] != "xprv" and serializedprivkey[:4] != "tprv"):
            raise TypeError("xprv/tprv key str required for first input.")
        if len(serializedprivkey) != 111:
            raise TypeError("xprv/tprv key str entered is not correct length, please check for errors.")
        try:
            keyhex, isValid = base58_decode(serializedprivkey,True,False)
        except:
            raise Exception("Error with Base58 decode attempt.")
        if not isValid:
            raise Exception("Base58 checksum mis-match.")
        privkeyhex = str(keyhex)[-64:]
        from pyBIP0038 import encrypt_privkey_from_password
        try:
            enc6Pkey = encrypt_privkey_from_password(password,privkeyhex,True)
        except Exception as e:
            raise Exception("Error attempting to encrypt prviate key. Possible bad password, but not 100% sure that was the problem. Exception thrown was: " + str(e))
        try:
            enchex, isValid = base58_decode(enc6Pkey,True,False)
        except:
            raise Exception("Error (1) encrypting key.")
        if not isValid:
            raise Exception("Error (2) encrypting key.")
        hashcheck = enchex[6:14]
        enckeyhex = enchex[14:]
        assert len(hashcheck) == 8
        assert len(enckeyhex) == 64
        if keyhex[:8] == "0488ade4":
            newkeyprefix = "282d214d"
        elif keyhex[:8] == "04358394":
            newkeyprefix = "254bfd62"
        else:
            raise Exception("Previously checked key for xprv/tprv but later check failed.")
        newkey = str(newkeyprefix + keyhex[8:-64] + hashcheck + enckeyhex)
        return base58_check_and_encode(newkey)

    @staticmethod
    def Bip38Decrypt(password,serializedenckey):
        """
        Decrypts a xp38/tp38 key created by previous method back into an xprv/tprv key.  Returns False instead of key str if password is incorrect.

        >>> Bip32Key.Bip38Decrypt("satoshi","xp38Fz45cvHGxGoybFU6Jq9JN1qkK9nENrQfPVmFi4ngcEGpmN9odFo1fTTEZWw8GKqFUpuUWBNg493MbXn2bmKpSZeKRrMcrRL5mFhJN29mPSrTCDbWd")
        'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
        >>> Bip32Key.Bip38Decrypt("dorian","xp38Fz45cvHGxGoybFU6Jq9JN1qkK9nENrQfPVmFi4ngcEGpmN9odFo1fTTEZWw8GKqFUpuUWBNg493MbXn2bmKpSZeKRrMcrRL5mFhJN29mPSrTCDbWd")
        False
        """

        if ('str' not in str(type(serializedenckey)) and 'unicode' not in str(type(serializedenckey))) or \
           (serializedenckey[:4] != "xp38" and serializedenckey[:4] != "tp38"):
            raise TypeError("xp38/tp38 key str required for first input.")
        if len(serializedenckey) != 117:
            raise TypeError("xprv/tprv key str entered is not correct length (117 chars), please check for errors.")
        try:
            enckeyhex, isValid = base58_decode(serializedenckey,True,False)
        except:
            raise Exception("Error with Base58 decode attempt.")
        if not isValid:
            raise Exception("Base58 checksum mis-match.")
        privkeyandhash = enckeyhex[-72:]
        bip386Pkeyhex = str("0142e0" + privkeyandhash)
        bip386Pkey = base58_check_and_encode(bip386Pkeyhex)
        assert bip386Pkey[:2] == "6P"
        from pyBIP0038 import decrypt_priv_key
        try:
            decryptedprivkey = decrypt_priv_key(password,bip386Pkey,False)
        except Exception as e:
            raise Exception("Error attempting to decrypt key. Exception thrown was:  " + str(e))
        if decryptedprivkey == False:
            return False
        decryptedprivkeyhex = base58_decode(decryptedprivkey,False,False)
        assert decryptedprivkeyhex[:2] == "80"
        assert decryptedprivkeyhex[-2:] == "01"
        decryptedprivkeyhex = decryptedprivkeyhex[2:-2]
        assert len(decryptedprivkeyhex) == 64
        if enckeyhex[:8] == "282d214d":
            newprefix = "0488ade4"
        elif enckeyhex[:8] == "254bfd62":
            newprefix = "04358394"
        else:
            raise Exception("Previously checked key for xprv/tprv but later check failed.")
        newkey = str(newprefix + enckeyhex[8:-72] + decryptedprivkeyhex)
        return base58_check_and_encode(newkey)

    @staticmethod
    def CKDpath(serializedparentkey,path="m",outputpub=False):
        """
        >>> Bip32Key.CKDpath("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi","m/0h/1/2h/2")
        'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'
        >>> Bip32Key.CKDpath("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi","m/234/567h",True)
        'xpub6Aa4ytjb9TqxthdETJgAYm8aHC5ggd7MQm7wf71wnCxs34hHSnMSzYyPiVn3t8HzhEHAY9684ggCgK3w61WgjRvR6RjL1f8viWSY2PRqzym'
        >>> Bip32Key.CKDpath("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8","m/234/567",True)
        'xpub6Aa4ytjSooJzhkxU8kWgapf8qLR6eT12MFiEjf6vAz11DPx5cqpJ39EgSFnWdhdCAUnsZugH7jCxF1Ljhx7ijfE9pS8kDrbj4zhzzTrTujD'
        """

        if outputpub == False and serializedparentkey[1:3] == "pub":
            raise Exception("Cannot output child private key from parent key input. If first input is xpub key, please make sure to set third input (outputpub) to True.")
        path = str(path).lower().replace(' ','').replace("'","h")
        if path[:1] != 'm':
            raise TypeError("Chain path must be in the format m/0/1h/2 ")
        for c in path:
            if c not in "1234567890mMhH'/ ":
                raise TypeError("Chain path must be in the format m/0/2h/4 ")
        if ('str' in str(type(serializedparentkey)) or 'unicode' in str(type(serializedparentkey))) and \
           (serializedparentkey[:4] == "xprv" or serializedparentkey[:4] == "xpub" or \
            serializedparentkey[:4] == "tprv" or serializedparentkey[:4] == "tpub"):
            if len(serializedparentkey) != 111:
                raise TypeError("xprv/xpub key str entered is not correct length, please check for errors.")
        else:
            raise TypeError("Input must be hex or serialized xprv/xpub key str. Input exception thrown was:  " + str(e))
        if path == "m":
            return serializedparentkey
        if serializedparentkey[1:4] == "pub" and "h" in path:
            raise Exception("Child path cannot contain any hardened keys since master parent key input is public.")
        pathlist = path.split("/")
        for i in range(len(pathlist)):
            if pathlist[i] == "m":
                newkey = serializedparentkey
            else:
                if newkey[1:4] == "prv":
                    newkey = Bip32Key.CKDpriv(newkey,pathlist[i])
                elif newkey[1:4] == "pub":
                    newkey = Bip32Key.CKDpub(newkey,pathlist[i])
                else:
                    raise Exception("Unknown error with child key derivation.  Input key passed first error check but failed later.")
        if outputpub and newkey[1:4] == "prv":
            newkey = Bip32Key.priv_to_pub(newkey)
        return newkey

    @staticmethod
    def CKDpriv(serializedparentkey,childindex):
        """
        >>> Bip32Key.CKDpriv("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",0)
        'xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R'
        >>> Bip32Key.CKDpriv("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi","0")
        'xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R'
        >>> Bip32Key.CKDpriv("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi","0H")
        'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'
        >>> Bip32Key.CKDpriv("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",234)
        'xprv9uHRZZhbkedWHevM4zVWB7XrNwPjKocGdNXnJ1NBZvYFkdZuQhJ58vuNwdeo1PUKdMJrNNs8mreDBm1gFr5hdnhZ632QYjXfPkpKmCSESyw'
        >>> Bip32Key.CKDpriv("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi","2147483882")
        'xprv9uHRZZhk6KAUVCoT4hJaRHYxNn7V66pku2ZBmR4ZYAPnCXY1sJyAcf9rtsQQeGKUPN45rYsFfHPGuXGtYEJbiMjA1JZvzM3ppFVzF62mTRM'
        >>> Bip32Key.CKDpriv("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",234 + 2**31)
        'xprv9uHRZZhk6KAUVCoT4hJaRHYxNn7V66pku2ZBmR4ZYAPnCXY1sJyAcf9rtsQQeGKUPN45rYsFfHPGuXGtYEJbiMjA1JZvzM3ppFVzF62mTRM'
        >>> Bip32Key.CKDpriv("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi","234h")
        'xprv9uHRZZhk6KAUVCoT4hJaRHYxNn7V66pku2ZBmR4ZYAPnCXY1sJyAcf9rtsQQeGKUPN45rYsFfHPGuXGtYEJbiMjA1JZvzM3ppFVzF62mTRM'
        """
        if ('str' not in str(type(serializedparentkey)) and 'unicode' not in str(type(serializedparentkey))) or \
           (serializedparentkey[:4] != "xprv" and serializedparentkey[:4] != "tprv"):
            raise TypeError("xprv/tprv key str required for first input.")
        if len(serializedparentkey) != 111:
            raise TypeError("xprv/tprv key str entered is not correct length, please check for errors.")
        if "h" in str(childindex) or "H" in str(childindex) or "'" in str(childindex):
            childindex = str(childindex).replace("h","").replace("H","").replace("'","")
            hardenchild = True
        else:
            hardenchild = False
        try:
            childindex = int(childindex)
        except:
            raise TypeError("Second input must be a positive index number integer, optionally with an 'H', 'h', or apostrophe \"'\" to signify a hardened child.")
        if hardenchild:
            childindex = childindex + 2**31
        if childindex >= 2**32 or childindex < 0:
            raise TypeError("Index number is out of range, please check for errors. A common error is to have an index number > 2**31 while also including an 'H'. 0H = 2**31; 2147483648H = TypeError exception")
        childindexhex = hexlify_(childindex,8)
        assert len(childindexhex) == 8
        parentkeyobject = Bip32Key(serializedparentkey)
        parentfpr = hash160(parentkeyobject.pubkey)[:8]
        newdepth = hexlify_(parentkeyobject.depth + 1,2)
        assert len(newdepth) == 2
        if childindex >= 2**31:
            bigI = hexlify_(hmac.new(binascii.unhexlify(parentkeyobject.chaincode),
                            binascii.unhexlify("00" + parentkeyobject.privkey + childindexhex),
                            hashlib.sha512).digest())
        else:
            bigI = hexlify_(hmac.new(binascii.unhexlify(parentkeyobject.chaincode),
                            binascii.unhexlify(parentkeyobject.pubkey + childindexhex),
                            hashlib.sha512).digest())
        assert len(bigI) == 128
        assert int(bigI[:-64],16) < N_ORDER and int(bigI[:-64],16) > 0
        childprivkey = add_privkeys(bigI[:-64],parentkeyobject.privkey)
        newchaincode = bigI[64:]
        return base58_check_and_encode(parentkeyobject.versionbytes + newdepth + parentfpr + childindexhex + 
                                       newchaincode + str("00") + childprivkey)

    @staticmethod
    def CKDpub(serializedparentkey,childindex):
        """
        >>> Bip32Key.CKDpub("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",0)
        'xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1'
        >>> Bip32Key.CKDpub("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8","234")
        'xpub68Gmy5EVb2BoW8zpB22WYFUavyEDjGL7zbTP6Pmo8G5EdRu3xEcKgjDrnwSUfUGuyiorbeXaeRbpuQEK2jGidvaT81MiGjBBKudg1DtUwAR'
        >>> Bip32Key.CKDpub("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",234)
        'xpub68Gmy5EVb2BoW8zpB22WYFUavyEDjGL7zbTP6Pmo8G5EdRu3xEcKgjDrnwSUfUGuyiorbeXaeRbpuQEK2jGidvaT81MiGjBBKudg1DtUwAR'
        """

        if ('str' not in str(type(serializedparentkey)) and 'unicode' not in str(type(serializedparentkey))) or \
           (serializedparentkey[:4] != "xpub" and serializedparentkey[:4] != "tpub"):
            raise TypeError("xpub/tpub key str required for first input.")
        if len(serializedparentkey) != 111:
            raise TypeError("xpub/tpub key str entered is not correct length, please check for errors.")
        if "h" in str(childindex) or "H" in str(childindex) or "'" in str(childindex):
            raise TypeError("Second input must be a positive index number integer less than 2**31. (2**31 to 2**32 not possible because public parent keys cannot create hardened child keys.)")
        try:
            childindex = int(childindex)
        except:
            raise TypeError("Second input must be a positive index number integer less than 2**31. (2**31 to 2**32 not possible because public parent keys cannot create hardened child keys.)")
        if childindex >= 2**32 or childindex < 0:
            raise TypeError("Index number is out of range, please check for errors.  Index input must be a positive index number integer less than 2**31. (2**31 to 2**32 not possible because public parent keys cannot create hardened child keys.)")
        elif childindex >= 2**31:
            raise TypeError("Index number > 2**31.  Public parent keys cannot create hardened child keys.")
        childindexhex = hexlify_(childindex,8)
        assert len(childindexhex) == 8
        parentkeyobject = Bip32Key(serializedparentkey)
        parentfpr = hash160(parentkeyobject.pubkey)[:8]
        newdepth = hexlify_(parentkeyobject.depth + 1,2)
        assert len(newdepth) == 2
        bigI = hexlify_(hmac.new(binascii.unhexlify(parentkeyobject.chaincode),
                                 binascii.unhexlify(parentkeyobject.pubkey + childindexhex),
                                 hashlib.sha512).digest())
        assert len(bigI) == 128
        assert int(bigI[:-64],16) < N_ORDER and int(bigI[:-64],16) > 0
        childpubkey = add_pubkeys(privkey_to_pubkey(bigI[:-64],True),parentkeyobject.pubkey)
        newchaincode = bigI[64:]
        return base58_check_and_encode(parentkeyobject.versionbytes + newdepth + parentfpr + childindexhex + 
                                       newchaincode + childpubkey)

    @staticmethod
    def priv_to_pub(serializedprivkey):
        """
        >>> Bip32Key.priv_to_pub("xprv9uHRZZhk6KAUVCoT4hJaRHYxNn7V66pku2ZBmR4ZYAPnCXY1sJyAcf9rtsQQeGKUPN45rYsFfHPGuXGtYEJbiMjA1JZvzM3ppFVzF62mTRM")
        'xpub68Gmy5EdvgimhgsvAiqanRVgvowyVZYcGFUnZoUB6Vvm5KsAQrHRATULk9pZj6jFNZpWgdcS2BVa9fvfrdJ2w9QdTUMwBBxi3grK1MYog5T'
        """
        if ('str' not in str(type(serializedprivkey)) and 'unicode' not in str(type(serializedprivkey))) or (serializedprivkey[:4] != "xprv" and serializedprivkey[:4] != "tprv"):
            raise TypeError("xprv/tprv key str required for input.")
        if len(serializedprivkey) != 111:
            raise TypeError("xprv/tprv key str entered is not correct length, please check for errors.")
        return Bip32Key(serializedprivkey).pub

    def __str__(self):
        return self.masterkey

if __name__ == "__main__":
    import doctest
    doctest.testmod()
