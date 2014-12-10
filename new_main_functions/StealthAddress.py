#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .ec_math import *
from .hexlify_permissive import *
from .hash_funcs import *
from .base58_hex_conversions import *
from .bitcoin_funcs import *
from .misc_funcs_and_vars import *
from .CoinFromKey import *

class StealthAddress(object):
    """
    A simple object to store all the variables about a stealth address.
    WARNING:  WIF and Bip38 enctyption format is not used anywhere else.
    I created them myself.

    WARNING:  All methods assume one scan key and one spend key.

    WARNING:  All methods assume version/options prefix of 0x2a00

    WARNING:  All methods not to do with dark wallet stealth sends assume prefix length 0x01 and prefix 0x00

    __str__ outputs public stealth address.

    >>> doctester = StealthAddress('9da7b31dbab89786a9ce2a2d2333e583cf6ef2138ddd2082027592615b4546c6', '4a54824ff9728f32fc59218762683758912fcf6f707cc39356966423ce554242')
    >>> str(doctester)
    'vJmuG7TooCtm8oPu9V6gWNrqAvaM1Tw24APmnsdpaBxxKp7QQGQM4ioZAXMqDLNAE6Ce9ZZDA8PtfEoxMxcbDK4uPw6u4NtHXJ8gms'
    >>> doctester.encrypted
    ''
    >>> doctester.privkeys
    ('9da7b31dbab89786a9ce2a2d2333e583cf6ef2138ddd2082027592615b4546c6', '4a54824ff9728f32fc59218762683758912fcf6f707cc39356966423ce554242')
    >>> doctester.privkey
    '9da7b31dbab89786a9ce2a2d2333e583cf6ef2138ddd2082027592615b4546c64a54824ff9728f32fc59218762683758912fcf6f707cc39356966423ce554242'
    >>> doctester.privkeyWIF
    '8UHyL3XzbtRVtH3sBu3F91AmSsnYdYwXvk2iASGmtCnr2eLov8L8vu1k3wuQ2yPaxZdfKCDZPDJAyNC7KV9U9oUeEYdek6W4'
    >>> doctester.scanpubkey
    '02819224626d731ddd6b7bc0a992a64dddaf40ef63d46d607ecd8134f49ba07159'
    >>> doctester.get_payment_privkey("028f417a702f0c05e83d20517f17be171edff70476b8f62db61b33a7c816da55a2")
    '212b5144d5b31d61aeabb0dc758317a10edd2d9ef79e052d17aa6cb49f45c599'
    >>> doctester.encrypt("satoshi")
    'bip38steaLthDJ71SbadSynvpozY9t5W1RMdzofsVcVx3RNcCG3nQXV55h3nv8ZSpgeCA6KtzVsEbfkSu35DhegjDHe5uBnfMXFoGwDLkmkaEKKqdMM'
    >>> doctester.encrypted
    'bip38steaLthDJ71SbadSynvpozY9t5W1RMdzofsVcVx3RNcCG3nQXV55h3nv8ZSpgeCA6KtzVsEbfkSu35DhegjDHe5uBnfMXFoGwDLkmkaEKKqdMM'
    >>> doctester.address == str(doctester)
    True
    """

    def __init__(self,scanprivkey=hexlify_(os.urandom(32),64),spendprivkey=hexlify_(os.urandom(32),64),version=str("2a"),options=str("00"),prefix_len=str("01"),prefix=str("00")):
        super(StealthAddress,self).__init__()
        self.scanprivkey = str(scanprivkey)
        self.spendprivkey = str(spendprivkey)
        self.encrypted = str("")
        for char in self.scanprivkey:
            if char not in '0123456789abcdefABCDEF':
                raise TypeError("Scan private key input must be 64 hex chars")
        for char in self.spendprivkey:
            if char not in '0123456789abcdefABCDEF':
                raise TypeError("Spend private key input must be 64 hex chars")
        try:
            version = hexlify_(binascii.unhexlify(version))
            options = hexlify_(binascii.unhexlify(options))
            prefix_len = hexlify_(binascii.unhexlify(prefix_len))
            prefix = hexlify_(binascii.unhexlify(prefix))
        except:
            raise Exception("Error with input for version, options, prefix_len, or prefix")
        assert len(self.scanprivkey) == 64
        assert len(self.spendprivkey) == 64
        assert int(prefix_len,16) < 9
        assert len(version) == 2
        assert len(options) == 2
        assert len(prefix_len) == 2
        assert len(prefix) == 2
        self.privkey = str(self.scanprivkey) + str(self.spendprivkey)
        self.privkeys = self.privkeys()
        privkeyversion = hexlify_(int(version,16) + int("80",16),2)
        assert len(privkeyversion) == 2
        self.privkeyWIF = base58_check_and_encode(str(privkeyversion) + str(options) + str(self.scanprivkey) + str(self.spendprivkey))
        self.scanpubkey = privkey_to_pubkey(self.scanprivkey,True)
        self.spendpubkey = privkey_to_pubkey(self.spendprivkey,True)
        self.address = base58_check_and_encode(str(version) + str(options) + str(self.scanpubkey) + str("01") + str(self.spendpubkey) + str(prefix_len) + str(prefix))

    def __str__(self):
        return self.address

    def privkeys(self):
        return self.scanprivkey, self.spendprivkey

    def get_payment_privkey(self,ephempubkey):
        return StealthAddress.derive_payment_privkey(self.scanprivkey,self.spendprivkey,ephempubkey)

    def encrypt(self,password):
        self.encrypted = StealthAddress.encrypt_privkeys(password,self.scanprivkey,self.spendprivkey)
        return self.encrypted

    @staticmethod
    def encrypt_privkeys(password,scanprivkey,spendprivkey):
        password = str(password)
        if int(sys.version_info.major) == 2:
            password = unicode(password)
        password = unicodedata.normalize('NFC',password)
        password = str(password)
        try:
            password = binascii.unhexlify(binascii.hexlify(password))
        except:
            password = binascii.unhexlify(binascii.hexlify(bytearray(password,'utf-8')))
        scanprivkey = str(scanprivkey)
        spendprivkey = str(spendprivkey)
        for char in scanprivkey:
            if char not in '0123456789abcdefABCDEF':
                raise TypeError("Scan private key input must be 64 hex chars")
        for char in spendprivkey:
            if char not in '0123456789abcdefABCDEF':
                raise TypeError("Spend private key input must be 64 hex chars")
        assert len(scanprivkey) == 64
        assert len(spendprivkey) == 64
        scanpubkey = privkey_to_pubkey(scanprivkey,True)
        spendpubkey = privkey_to_pubkey(spendprivkey,True)
        from pyBIP0038 import aes_encrypt_bip38
        # import random # random just used for padding char
        try:
            import scrypt
        except:
            import pyscrypt as scrypt
        # Creates "bip38steaLth" prefix for base58 encoding of 81 bytes
        magicBytes = '01e6ed994de37ff04d5' # Missing last char, see next lines
        # Last char can be reserved for misc use.
        # Byte range that keeps the "h" in "bip38steaLth" is 0x53 to 0x5d
        # For deteministic consistency, I'm setting it at '5', but it could
        # be changed to anything that works.  The decrypt function doesn't care
        lastchar = '5' # magicBytes = '01e6ed994de37ff04d55'

        #list1 = ['3','4','5','6','7','8','9','a','b','c','d']
        #lastchar = list1[int(random.randrange(len(list1)))]

        magicBytes = magicBytes + lastchar
        list1, lastchar = "",""
        flagByte = 'e0' # Using BIP0038 flag, compressed keys, no ec 
                             # multiplication. This may be pointless, and in
                             # the future should be used for other info.
        versionBytes = 'aa00' # 2a + 80 = aa, misc version info = 00
        try:
            addresshash = sha256(sha256(binascii.hexlify(str(pubkey_to_address(scanpubkey,'00')) + \
                                                     str(pubkey_to_address(spendpubkey,'00')))))[:8]
        except:
            addresshash = sha256(sha256(binascii.hexlify(bytearray(str(pubkey_to_address(scanpubkey,'00')) + \
                                                     str(pubkey_to_address(spendpubkey,'00')),'utf-8'))))[:8]
        scryptSalt = binascii.unhexlify(addresshash)
        scryptHash = hexlify_(scrypt.hash(password,scryptSalt,16384,8,8,64))
        assert len(scryptHash) == 128
        scryptSalt = ""
        msg1a = binascii.unhexlify(hexlify_(int(scanprivkey[:-32],16) ^ int(scryptHash[:-96],16)))
        msg1b = binascii.unhexlify(hexlify_(int(scanprivkey[32:],16) ^ int(scryptHash[32:-64],16)))
        encScanKey = str(hexlify_(aes_encrypt_bip38(msg1a,binascii.unhexlify(scryptHash[64:])))) + str(hexlify_(aes_encrypt_bip38(msg1b,binascii.unhexlify(scryptHash[64:]))))
        newPass = binascii.unhexlify(sha256(hexlify_(password)))
        newSalt = binascii.unhexlify(sha256(str(hexlify_(newPass)) + str(addresshash))[:8])
        scryptHash2 = hexlify_(scrypt.hash(newPass,newSalt,16384,8,8,64))
        assert len(scryptHash2) == 128
        msg2a = binascii.unhexlify(hexlify_(int(spendprivkey[:-32],16) ^ int(scryptHash2[:-96],16)))
        msg2b = binascii.unhexlify(hexlify_(int(spendprivkey[32:],16) ^ int(scryptHash2[32:-64],16)))
        encSpendKey = str(hexlify_(aes_encrypt_bip38(msg2a,binascii.unhexlify(scryptHash2[64:])))) + str(hexlify_(aes_encrypt_bip38(msg2b,binascii.unhexlify(scryptHash2[64:]))))
        return base58_check_and_encode(str(magicBytes) + str(versionBytes) + \
                                       str(flagByte) + str(addresshash) + \
                                       str(encScanKey) + str(encSpendKey))

    @staticmethod
    def decrypt_privkeys(password,encKey):
        """
        Decrypts a "bip0038 enctyped" stealth private key.  Sarcasm quotes used
        because I made up the method and it's not officially a BIP0038 specification.

        See the StealthAddress class for the encryption method.

        >>> StealthAddress.decrypt_privkeys("satoshi","bip38steaLthDJ71SbadSynvpozY9t5W1RMdzofsVcVx3RNcCG3nQXV55h3nv8ZSpgeCA6KtzVsEbfkSu35DhegjDHe5uBnfMXFoGwDLkmkaEKKqdMM")
        ('9da7b31dbab89786a9ce2a2d2333e583cf6ef2138ddd2082027592615b4546c6', '4a54824ff9728f32fc59218762683758912fcf6f707cc39356966423ce554242')
        >>> StealthAddress.decrypt_privkeys("dorian","bip38steaLthDJ71SbadSynvpozY9t5W1RMdzofsVcVx3RNcCG3nQXV55h3nv8ZSpgeCA6KtzVsEbfkSu35DhegjDHe5uBnfMXFoGwDLkmkaEKKqdMM")
        (False, False)
        """

        from pyBIP0038 import aes_decrypt_bip38
        try:
            import scrypt
        except:
            import pyscrypt as scrypt
        password = str(password)
        if int(sys.version_info.major) == 2:
            password = unicode(password)
        password = unicodedata.normalize('NFC',password)
        password = str(password)
        try:
            password = binascii.unhexlify(binascii.hexlify(password))
        except:
            password = binascii.unhexlify(binascii.hexlify(bytearray(password,'utf-8')))
        if len(encKey) != 115 or encKey[:11] != 'bip38steaLt':
            raise TypeError("Second input must be encrypted stealth private key str, beginning with 'bip38steaLth'")
        encKeyHex, isValid = base58_decode(encKey,True,False)
        if not isValid:
            raise Exception("Base58 decode checksum fail")
        assert len(encKeyHex) == 162
        magicBytes = encKeyHex[:-142]
        versionBytes = encKeyHex[20:-138]
        flagByte = encKeyHex[24:-136]
        salt = str(encKeyHex[26:-128])
        encryptedHalf1 = binascii.unhexlify(encKeyHex[34:-96])
        encryptedHalf2 = binascii.unhexlify(encKeyHex[66:-64])
        encryptedHalf3 = binascii.unhexlify(encKeyHex[98:-32])
        encryptedHalf4 = binascii.unhexlify(encKeyHex[130:])
        scryptSalt = binascii.unhexlify(salt)
        scryptHash = hexlify_(scrypt.hash(password,scryptSalt,16384,8,8,64))
        assert len(scryptHash) == 128
        newPass = binascii.unhexlify(sha256(binascii.hexlify(password)))
        newSalt = binascii.unhexlify(sha256(str(hexlify_(newPass)) + str(salt))[:8])
        scryptHash2 = hexlify_(scrypt.hash(newPass,newSalt,16384,8,8,64))
        assert len(scryptHash2) == 128
        decryption1 = hexlify_(aes_decrypt_bip38(encryptedHalf1,binascii.unhexlify(scryptHash[64:])))
        decryption2 = hexlify_(aes_decrypt_bip38(encryptedHalf2,binascii.unhexlify(scryptHash[64:])))
        decryption3 = hexlify_(aes_decrypt_bip38(encryptedHalf3,binascii.unhexlify(scryptHash2[64:])))
        decryption4 = hexlify_(aes_decrypt_bip38(encryptedHalf4,binascii.unhexlify(scryptHash2[64:])))
        privKey1Half1 = hexlify_(int(decryption1,16) ^ int(scryptHash[:-96],16))
        privKey1Half2 = hexlify_(int(decryption2,16) ^ int(scryptHash[32:-64],16))
        privKey2Half1 = hexlify_(int(decryption3,16) ^ int(scryptHash2[:-96],16))
        privKey2Half2 = hexlify_(int(decryption4,16) ^ int(scryptHash2[32:-64],16))
        privKey1 = str(privKey1Half1) + str(privKey1Half2)
        privKey2 = str(privKey2Half1) + str(privKey2Half2)
        pub1 = pubkey_to_address(privkey_to_pubkey(privKey1,True),'00')
        pub2 = pubkey_to_address(privkey_to_pubkey(privKey2,True),'00')
        try:
            checksum = str(sha256(sha256(binascii.hexlify(str(pub1) + str(pub2))))[:8])
        except:
            checksum = str(sha256(sha256(binascii.hexlify(bytearray(str(pub1) + str(pub2),'utf-8'))))[:8])
        if checksum != salt:
            return False, False
        else:
            return privKey1, privKey2

    @staticmethod
    def stealth_derive_key_to_pay(stealthaddress,ephemprivkey=hexlify_(os.urandom(32),64)):
        """
        Takes a 'vJm' stealth address, and returns two compressed public keys.
        The first key is the address to pay, the second is the public ephemeral key.

        >>> StealthAddress.stealth_derive_key_to_pay("vJmuqwbjTC73dt8JfxsS1LerjiGG5tkKNNyqNLtMq7eL4dDJuK8tMWzQaC785ipzUNHCWZXAQfhsZ66jKGKrcK6wFfpvw6hq7PbgXQ","afe0ce8731951f866ac85bb20613a321a169a2d216f208c646f1407b7b44a07f")
        ('02a0a9dd0f63858dd345d4a107a45b7ddb801cc4ecef85f0895241941a0ffa69d6', '020acf156ffda03d45a2b32ff98d09c348e711bb45b72ee880433eab8394e5553d')
        >>> StealthAddress.stealth_derive_key_to_pay("vJmwBpVNgQtu8kLfK3ChKCs45uWBcQiV135SXHueL9uJM9r26QrMDhjsL2nQivvEGjoZPHMY7zXxXzpU9vHDx81aBAGXsFu2SnhnwJ","ff6982685a3d887964ba7ccb3b33ac0f5b6e7bf4b1659926a42b64b53bdb650f")
        ('03b80a6c950d6eb4dd68732af3c64656a5c6e33358406ad8812267966923f7e9e7', '03261f43b8cedfe946e879f67ee4f662e11b7b02b84294b158500cf18d4908b1f4')
        """

        if len(stealthaddress) != 102 or stealthaddress[:3] != "vJm":
            raise TypeError("Stealth address input must be a 102-char string beginning with 'vJm'")
        for char in ephemprivkey:
            if char not in '0123456789abcdefABCDEF':
                raise TypeError("Ephemeral private key input must be 64 hex chars")
        assert len(ephemprivkey) == 64
        try:
            stealthHexStr, isValid = base58_decode(stealthaddress,True,False)
        except:
            raise Exception('Unknown error while attempting to decode stealth address into hex.')
        if not isValid:
            raise Exception('Base58 decode checksum fail on stealth address input.')
        compressedScanPubKey = stealthHexStr[4:-72]
        compressedSpendPubKey = stealthHexStr[72:-4]
        if ((compressedScanPubKey[:2] != '02') and (compressedScanPubKey[:2] != '03')) or \
           ((compressedSpendPubKey[:2] != '02') and (compressedSpendPubKey[:2] != '03')):
            raise Exception('Stealth key input contains unknown key error')
        compressedEphemPubKey = privkey_to_pubkey(ephemprivkey,True)
        sharedSecret = sha256(multiply_pub_and_priv(compressedScanPubKey,ephemprivkey,True))
        assert len(sharedSecret) == 64
        compressedPayPubKey = add_pubkeys(compressedSpendPubKey,privkey_to_pubkey(sharedSecret,True),True)
        return compressedPayPubKey, compressedEphemPubKey

    @staticmethod
    def generate_DW_compatible_nonce(stealthaddress,ephemprivkey=double_sha256(hexlify_(os.urandom(32),64)),_doctest_nonce=(int(double_sha256(hexlify_(os.urandom(32))),16) % (2**32))):
        """
        Tries to find a working nonce for the given stealth address and ephemeral key input.  Ouputs nonce hexstr if found, otherwise returns False.  (OP_RETURN data is 06+NONCE_HEX+ephemeral_pubkey)

        Much code taken from lines 175-230 of:
        https://github.com/dabura667/electrum/blob/sendstealth/lib/bitcoin.py
        """

        if len(stealthaddress) != 102 or stealthaddress[:3] != "vJm":
            raise TypeError("Stealth address input must be a 102-char string beginning with 'vJm'")
        try:
            stealthHexStr, isValid = base58_decode(stealthaddress,True,False)
        except:
            raise Exception('Unknown error while attempting to decode stealth address into hex.')
        if not isValid:
            raise Exception('Base58 decode checksum fail on stealth address input.')
        try:
            ephemprivkey = hexlify_(unhexlify_(ephemprivkey))
        except:
            raise Exception("Invalid ephemeral private key input.  Input must be hex.")
        assert len(ephemprivkey) == 64
        prefix_len, prefix = int(stealthHexStr[-4:-2],16), binascii.unhexlify(stealthHexStr[-2:])
        x, ephemst = StealthAddress.stealth_derive_key_to_pay(stealthaddress,ephemprivkey); x = None
        nonce = int(_doctest_nonce)
        firstnonce = nonce
        while True:
            nonce = nonce + 1
            if nonce > 4294967295:
                nonce = 0
            if nonce == firstnonce:
                return False
            noncest = hexlify_(nonce,8)
            hashprefix = (binascii.unhexlify(double_sha256(str(str('6a2606') + str(noncest) + str(ephemst)))))[::-1][:4]
            if StealthAddress.check_prefix(prefix_len, prefix, hashprefix) or prefix_len == 0:
                return str(noncest)
        return False

    @staticmethod
    def check_prefix(pre_num, prefix, p_hash):
        """
        Lines 213-228
        https://github.com/dabura667/electrum/blob/sendstealth/lib/bitcoin.py
        """

        if pre_num == 0: return True
        assert len(p_hash) == 4, _("Hash head size incorrect")
        prebits = pre_num
        byte_pos = 0
        while prebits > 8: # This compares the first complete bytes as bytes if the pre_num is higher than 8 bits
            if prefix[byte_pos] != p_hash[byte_pos]:
                return False
            prebits = prebits - 8
            byte_pos = byte_pos + 1
        prefixhex = hexlify_(prefix[byte_pos])
        if prefixhex == "": prefixhex = binascii.hexlify(b"00")
        p_hashhex = hexlify_(p_hash[byte_pos])
        if p_hashhex == "": p_hashhex =  binascii.hexlify(b"00")
        prefix_bits = (((1 << (8 - prebits)) - 1) ^ 0xff) & int(prefixhex, 16)
        hash_bits = (((1 << (8 - prebits)) - 1) ^ 0xff) & int(p_hashhex, 16)
        if prefix_bits == hash_bits:
            return True
        else:
            return False

    @staticmethod
    def darkwallet_stealth_send(stealthaddress,ephemprivkey=double_sha256(hexlify_(os.urandom(32),64)),tryonekey=False,_doctest_nonce=(int(double_sha256(hexlify_(os.urandom(32))),16) % (2**32))):
        """
        Generates a valid nonce/ephemkey pair and returns a tuple of payment address and full OP_RETURN data

        # Regular address with prefix length 1, prefix of 0x00, nonce iterating starting at 1234567890
        >>> StealthAddress.darkwallet_stealth_send("vJmwrTPckg7uEZ72BgcGzXSdxerP2znSSuyVr11nXbKn7GH1Nkd3AJFdpDGzNu9QaWfKS4ov9k2yxJN6ECMkfFiBQmn5oJJ7wXLmu1","bbff1fd36f5b234fba0876d5a62a1bb9ac026ac88e65bead2f00961c2862132c",True,1234567890)
        ('03d765834a659d0c300f588fd2dbe07366f9006a825224de45e32f098d1cb26943', '06499602d302e556af90473d1756c5340d978957ae304d87b883c11dcb1eb0fb0a87cd552b28')

        # prefix length 8, prefix 0x00, nonce iterating starting at 0
        >>> StealthAddress.darkwallet_stealth_send("vJmwrTPckg7uEZ72BgcGzXSdxerP2znSSuyVr11nXbKn7GH1Nkd3AJFdpDGzNu9QaWfKS4ov9k2yxJN6ECMkfFiBQmn5oJMc9Qr1oM","bbff1fd36f5b234fba0876d5a62a1bb9ac026ac88e65bead2f00961c2862132c",True,0)
        ('03d765834a659d0c300f588fd2dbe07366f9006a825224de45e32f098d1cb26943', '06000002db02e556af90473d1756c5340d978957ae304d87b883c11dcb1eb0fb0a87cd552b28')

        # prefix length 8, prefix 0xff, nonce iterating starting at 0
        >>> StealthAddress.darkwallet_stealth_send("vJmwrTPckg7uEZ72BgcGzXSdxerP2znSSuyVr11nXbKn7GH1Nkd3AJFdpDGzNu9QaWfKS4ov9k2yxJN6ECMkfFiBQmn5oJN6r6jUWY","bbff1fd36f5b234fba0876d5a62a1bb9ac026ac88e65bead2f00961c2862132c",True,0)
        ('03d765834a659d0c300f588fd2dbe07366f9006a825224de45e32f098d1cb26943', '060000006002e556af90473d1756c5340d978957ae304d87b883c11dcb1eb0fb0a87cd552b28')
        """

        if len(stealthaddress) != 102 or stealthaddress[:3] != "vJm":
            raise TypeError("Stealth address input must be a 102-char string beginning with 'vJm'")
        try:
            stealthHexStr, isValid = base58_decode(stealthaddress,True,False)
        except:
            raise Exception('Unknown error while attempting to decode stealth address into hex.')
        if not isValid:
            raise Exception('Base58 decode checksum fail on stealth address input.')
        try:
            ephemprivkey = hexlify_(binascii.unhexlify(ephemprivkey))
            assert len(str(ephemprivkey)) == 64
        except:
            raise Exception("Invalid ephemeral private key input.")
        while True:
            while True:
                nonce = StealthAddress.generate_DW_compatible_nonce(stealthaddress,ephemprivkey,_doctest_nonce)
                if nonce:
                    break
            if tryonekey:
                break
            else:
                if nonce:
                    break
                else:
                    ephemprivkey = double_sha256(hexlify_(os.urandom(32),64))
        if nonce == False:
            raise Exception("No nonce found for given ephemeral key")
        assert len(str(nonce)) == 8
        paypubkey, ephempubkey = StealthAddress.stealth_derive_key_to_pay(stealthaddress,ephemprivkey)
        opreturndata = str("06") + str(nonce) + str(ephempubkey)
        return str(paypubkey), str(opreturndata)

    @staticmethod
    def derive_payment_privkey(scanprivkey,spendprivkey,ephempubkey):
        """
        Gets the 64-char hex private key for a stealth payment.

        >>> StealthAddress.derive_payment_privkey("34f8dba121e9778219419fc7db600d49e7a2a5b782cecac813c6e456163f739c","2c1927ff1e45d9d679351100745fe017f660b99043a35cb69256239324d303c1","03b8318c184aedd048ce10379b6085674ca0a34db3fb163a6b5945adbac9fc6be1")
        '49547f6c63e6fb4036b5bb1cfd9e092ee7c65723e71ab72abb50008c6fff6797'
        """

        for char in scanprivkey:
            if char not in '0123456789abcdefABCDEF':
                raise TypeError("Scan private key input must be 64 hex chars")
        for char in spendprivkey:
            if char not in '0123456789abcdefABCDEF':
                raise TypeError("Spend private key input must be 64 hex chars")
        for char in ephempubkey:
            if char not in '0123456789abcdefABCDEF':
                raise TypeError("Ephemeral public key input must be 66 hex chars (compressed)")
        assert len(scanprivkey) == 64
        assert len(spendprivkey) == 64
        assert len(ephempubkey) == 66
        sharedSecret = sha256(multiply_pub_and_priv(ephempubkey,scanprivkey,True))
        payprivkey = add_privkeys(sharedSecret,spendprivkey)
        return payprivkey

    @staticmethod
    def WIF_to_privkeys(wifprivkey):
        """
        WARNING:  WIF format is not used anywhere else.  I created it myself.

        >>> StealthAddress.WIF_to_privkeys("8UHybkQpep5AE6PRJ9Fus7dnNH8co9eWpAh4dJFaaPSRmHg8V4fC3XgErh8RttaFEcuum1YjSZMUNZyn6oe9cGCCW9voewB4")
        ('9fb98907c7220e9ce11f09b310591ffc142e366f35873723070a4db57cddea65', '938fb915cfb48466bacb8823570b60575a5c6ee99fbb1add916e426acd9d421b')
        """

        wifprivkey = str(wifprivkey)
        if len(wifprivkey) != 96 or wifprivkey[:2] != '8U':
            raise TypeError("Input key must be a 96 char base58 encoded string beginning with '8U'")
        try:
            stealthkeys, isValid = base58_decode(wifprivkey,True,False)
        except:
            raise Exception("Unknown error attempting to base58 decode input.")
        if not isValid:
            raise Exception("Base58 decode checksum fail")
        assert len(stealthkeys) == 132
        if stealthkeys[:4] != 'aa00':
            raise Exception("Unknown WIF version identifier")
        return str(stealthkeys[4:-64]), str(stealthkeys[-64:])

if __name__ == "__main__":
    import doctest
    doctest.testmod()
