#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .ec_math import *
from .hexlify_permissive import *
from .hash_funcs import *
from .base58_hex_conversions import *

def uncompress_pubkey(compressedPubKey):
    """
    Turn a 02/03 prefix public key into an uncompressed 04 key.

    pow_mod() and most of this function taken from:
    https://bitcointalk.org/index.php?topic=644919.msg7205689#msg7205689

    >>> uncompress_pubkey("026C6A02AD4C2DC74091DC10B04EC8EB255BCA5480C9D782C7510E4E4E02AD25AB")
    '046c6a02ad4c2dc74091dc10b04ec8eb255bca5480c9d782c7510e4e4e02ad25abeb6228aaa8a25e47c01def7f04bdd0485c7535886161e94a1be568bc859c0db4'
    """

    try:
        compressedPubKey = hexlify_(binascii.unhexlify(compressedPubKey))
        test2 = int(compressedPubKey,16)
        test1,test2 = "",""
    except:
        raise TypeError("Input is not in correct format. Must be 66 char hex string, beginning with '02' or '03'.")
    compressedPubKey = str(compressedPubKey)
    if len(compressedPubKey) == 130 and compressedPubKey[:2] == "04":
        raise TypeError("Input key is already uncompressed.")
    elif (len(compressedPubKey) != 66) \
     or ((compressedPubKey[:-64] != '02') \
      and (compressedPubKey[:-64] != '03')):
        raise TypeError("Input appears to be hex but is not in the correct format. Must be 66 char hex string, beginning with '02' or '03'.")
    assert len(compressedPubKey) == 66
    y_parity = int(compressedPubKey[:2],16) - 2
    x = int(compressedPubKey[2:],16)
    a = (pow_mod(x, 3, P_FINITE_FIELD) + 7) % P_FINITE_FIELD
    y = pow_mod(a, (P_FINITE_FIELD+1)//4, P_FINITE_FIELD)
    if y % 2 != y_parity:
        y = -y % P_FINITE_FIELD
    x = hexlify_(x,64)
    y = hexlify_(y,64)
    return hexlify_(unhexlify_(str(str('04') + str(x) + str(y))))

def compress_pub_key(uncompressedPubKey):
    """
    Compress an 04 prefix public key to a 02/03 key

    >>> compress_pub_key("046c6a02ad4c2dc74091dc10b04ec8eb255bca5480c9d782c7510e4e4e02ad25abeb6228aaa8a25e47c01def7f04bdd0485c7535886161e94a1be568bc859c0db4")
    '026c6a02ad4c2dc74091dc10b04ec8eb255bca5480c9d782c7510e4e4e02ad25ab'
    """

    try:
        test1 = binascii.hexlify(binascii.unhexlify(uncompressedPubKey))
        test2 = int(uncompressedPubKey,16)
        test1,test2 = "",""
    except:
        raise TypeError("Input is not in correct format. Must be 130 char hex string, beginning with '04'.")
    uncompressedPubKey = str(uncompressedPubKey)
    if len(uncompressedPubKey) == 66 and ((compressedPubKey[:2] == '02') or (compressedPubKey[:2] == '03')):
        raise TypeError("Input key is already compressed.")
    elif uncompressedPubKey[:2] != '04' or len(uncompressedPubKey) != 130:
        raise TypeError("Input appears to be hex but is not in the correct format. Must be 130 char hex string, beginning with '04'.")
    x_coordStr = uncompressedPubKey[2:66]
    y_coordStr = uncompressedPubKey[66:]
    if int(y_coordStr,16) % 2:
        outputHexStr = '03' + x_coordStr
    else:
        outputHexStr = '02' + x_coordStr
    return hexlify_(unhexlify_(outputHexStr))

def privkey_to_hexstr(privkey_unknownformat):
    # Most functions and methods still require hex privkey inputs.
    # This function is just to make that hex easier to get.
    # I avoided having other functions call this one in order to force myself to be more clear when I code.
    """
    >>> privkey_to_hexstr("24A40CD9E3ACAAB0E575F1E938C466EE4A0DB6C68F00955F850237B10FE1F906")
    '24a40cd9e3acaab0e575f1e938c466ee4a0db6c68f00955f850237b10fe1f906'
    >>> privkey_to_hexstr("5J6RXEcyPbdGiBt6gwthBzqZfoA2BC8gWHpe1Eq5y5mdEum4KFr")
    '24a40cd9e3acaab0e575f1e938c466ee4a0db6c68f00955f850237b10fe1f906'
    >>> privkey_to_hexstr("KxSwET7mtjq6Lo2Y7KHAPYHMCEipBz8uNHFGL43EvY3xx3KKN2C2")
    '24a40cd9e3acaab0e575f1e938c466ee4a0db6c68f00955f850237b10fe1f906'
    >>> privkey_to_hexstr("WTchpuheKesrXXy5NhJZutzvs5z8ThPWveUX4JdxnWZVwYVkj3Qa")
    '24a40cd9e3acaab0e575f1e938c466ee4a0db6c68f00955f850237b10fe1f906'
    """

    try:
        privkey = hexlify_(unhexlify_(privkey_unknownformat))
    except:
        privkey, isValid = base58_decode(privkey_unknownformat,True,False)
        if not isValid:
            raise Exception("Base58 checksum mis-match on decode")
    if len(privkey) == 68:
        assert privkey[-2:] == "01"
        privkey = privkey[:-2]
    if len(privkey) == 66:
        privkey = privkey[2:]
    assert len(privkey) == 64
    return hexlify_(binascii.unhexlify(privkey))

def privkey_to_pubkey(privkey,compressed=True):
    """
    Derive public key from private key hex input

    >>> privkey_to_pubkey("c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a",False)
    '0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455'
    >>> privkey_to_pubkey("c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a")
    '0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'
    """

    try:
        privkey = hexlify_(unhexlify_(privkey))
        assert len(privkey) == 64
        privkeyInt = int(privkey,16)
    except:
        raise TypeError("Private key input is not hex, is wrong size, or is odd length.")
    pubX, pubY = ec_multiply(GENERATOR_POINT_XCOORD,GENERATOR_POINT_YCOORD,privkeyInt)
    pubX = hexlify_(pubX,64)
    pubY = hexlify_(pubY,64)
    uncompressedpub = hexlify_(binascii.unhexlify('04' + pubX + pubY))
    assert len(uncompressedpub) == 130
    if compressed:
        return compress_pub_key(uncompressedpub)
    else:
        return uncompressedpub

def add_privkeys(privkey1,privkey2):
    """
    Adds two private keys modulo the order of the curve, which results in the
    private key which corresponds to the public key which is the result of
    adding two public keys.

    That is:  pubkey1 + pubkey2 = pubkey3, and privkey1 + privkey2 = privkey3

    >>> add_privkeys("7e7395003b827028dca7d3a2f033b3c2870f857d44be1af1f5bf41ec6db697cc","cbe0f8487a0272c2fe97cf2a6fe70ab5ee2a60084fad5e5439fbb526693ed142")
    '4a548d48b584e2ebdb3fa2cd601abe79ba8b089ee522d90a6fe8988606bf27cd'
    """

    try:
        privkey1 = hexlify_(unhexlify_(privkey1))
        privkey1Int = int(privkey1,16)
    except:
        raise TypeError("Private key 1 input is not hex or is odd length.")
    try:
        privkey2b = hexlify_(binascii.unhexlify(privkey2))
        privkey2Int = int(privkey2,16)
    except:
        raise TypeError("Private key 2 input is not hex or is odd length.")
    if len(privkey1) != 64 or privkey1Int > N_ORDER:
        raise TypeError("Private key 1 input hex is wrong size, or when converted to an integer it is greater than or equal to N.  Input should be hex of length 32 bytes (64 chars) and between 1 and N-1.")
    if len(privkey2) != 64 or privkey2Int > N_ORDER:
        raise TypeError("Private key 2 input hex is wrong size, or when converted to an integer it is greater than or equal to N.  Input should be hex of length 32 bytes (64 chars) and between 1 and N-1.")
    return hexlify_(int((privkey1Int + privkey2Int) % N_ORDER),64)

def multiply_privkeys(privkey1,privkey2):
    """
    Multiply two private keys modulo the order of the curve, which results in the
    private key which corresponds to the public key that is the result of
    multiplying a private key by a public key and vice versa.

    That is:  privkey1*pubkey2 = pubkey3, and pubkey1*privkey2 = pubkey3, and privkey1*privkey2 = privkey3

    >>> multiply_privkeys("7e7395003b827028dca7d3a2f033b3c2870f857d44be1af1f5bf41ec6db697cc","cbe0f8487a0272c2fe97cf2a6fe70ab5ee2a60084fad5e5439fbb526693ed142")
    '07e68fcab5fad3f12b7260ba219ee66deb9c058259f643183717038d1b02a08e'
    """

    try:
        privkey1 = hexlify_(unhexlify_(privkey1))
        privkey1Int = int(privkey1,16)
    except:
        raise TypeError("Private key 1 input is not hex or is odd length.")
    try:
        privkey2 = hexlify_(unhexlify_(privkey2))
        privkey2Int = int(privkey2,16)
    except:
        raise TypeError("Private key 2 input is not hex or is odd length.")
    if len(privkey1) != 64 or privkey1Int > N_ORDER:
        raise TypeError("Private key 1 input hex is wrong size, or when converted to an integer it is greater than or equal to N.  Input should be hex of length 32 bytes (64 chars) and between 1 and N-1.")
    if len(privkey2) != 64 or privkey2Int > N_ORDER:
        raise TypeError("Private key 2 input hex is wrong size, or when converted to an integer it is greater than or equal to N.  Input should be hex of length 32 bytes (64 chars) and between 1 and N-1.")
    return hexlify_(int((privkey1Int*privkey2Int) % N_ORDER),64)

def multiply_pub_and_priv(pubkey,privkey,outputCompressed=True):
    """
    Multiply a public key by a private key, which outputs a public key.
    Useful for the fact that priv1*pub2 = pub1*priv2 = pubkey3.  This
    allows two people to create a shared secret, pubkey3.

    >>> multiply_pub_and_priv("02626d64aaed6eafc082a32f01c35a8909a69226031175d2cf3e7498f3b13796ed","cbe0f8487a0272c2fe97cf2a6fe70ab5ee2a60084fad5e5439fbb526693ed142")
    '03b097caf47eaf3f2d59fe170ce8ef2867432598d75d253dec7c20f1ab0489f5b5'
    >>> multiply_pub_and_priv("02e4b2672b7db8619c1847076012719afb4baa61e227c33555555e8a84e00395e8","7e7395003b827028dca7d3a2f033b3c2870f857d44be1af1f5bf41ec6db697cc")
    '03b097caf47eaf3f2d59fe170ce8ef2867432598d75d253dec7c20f1ab0489f5b5'
    >>> multiply_pub_and_priv("02e4b2672b7db8619c1847076012719afb4baa61e227c33555555e8a84e00395e8","7e7395003b827028dca7d3a2f033b3c2870f857d44be1af1f5bf41ec6db697cc",False)
    '04b097caf47eaf3f2d59fe170ce8ef2867432598d75d253dec7c20f1ab0489f5b50f04234abb54a852b12be707f0f2e24912abe3b88ff130535b32e74913440da7'
    >>> multiply_pub_and_priv("04e4b2672b7db8619c1847076012719afb4baa61e227c33555555e8a84e00395e83ec5245a1783cc3e571bbeefc53597217e2498a7621a6507bdd96c252c734df4","7e7395003b827028dca7d3a2f033b3c2870f857d44be1af1f5bf41ec6db697cc",False)
    '04b097caf47eaf3f2d59fe170ce8ef2867432598d75d253dec7c20f1ab0489f5b50f04234abb54a852b12be707f0f2e24912abe3b88ff130535b32e74913440da7'
    >>> multiply_pub_and_priv("04e4b2672b7db8619c1847076012719afb4baa61e227c33555555e8a84e00395e83ec5245a1783cc3e571bbeefc53597217e2498a7621a6507bdd96c252c734df4","7e7395003b827028dca7d3a2f033b3c2870f857d44be1af1f5bf41ec6db697cc",True)
    '03b097caf47eaf3f2d59fe170ce8ef2867432598d75d253dec7c20f1ab0489f5b5'
    """

    try:
        privkey = hexlify_(unhexlify_(privkey))
        privkeyInt = int(privkey,16)
    except:
        raise TypeError("Private key 1 input is not hex or is odd length.")
    if len(privkey) != 64 or privkeyInt > N_ORDER:
        raise TypeError("Private key input hex is wrong size, or when converted to an integer it is greater than or equal to N.  Input should be hex of length 32 bytes (64 chars) and between 1 and N-1.")
    try:
        pubkey = hexlify_(unhexlify_(pubkey))
        pubkeyInt = int(pubkey,16)
        pubkeyInt = ""
    except:
        raise TypeError("Public key input is not hex or is odd length.")
    if len(pubkey) == 130:
        if pubkey[:2] != '04':
            raise TypeError("Public key length is 130 chars but pubkey[:2] is not '04'.")
    elif len(pubkey) == 66:
        if pubkey[:2] != '02' and pubkey[:2] != '03':
            raise TypeError("Public key length is 66 chars but pubkey[:2] is not '02' or '03'.")
    else:
        raise TypeError("Public key input hex does not appear to be a public key. Please check input for errors.")
    if len(pubkey) == 66:
        pubkey = uncompress_pubkey(pubkey)
    pubXint, pubYint = int(pubkey[2:-64],16), int(pubkey[-64:],16)
    outX, outY = ec_multiply(pubXint,pubYint,privkeyInt)
    outX, outY = hexlify_(outX,64), hexlify_(outY,64)
    if outputCompressed:
        return compress_pub_key(str("04" + outX + outY))
    else:
        return str("04" + outX + outY)

def add_pubkeys(pubkey1,pubkey2,outputCompressed=True):
    """
    Add two public keys.  This results in the public key which corresponds
    to the private key which was the result of adding the two private keys
    which belong to the public key inputs.

    That is:  pubkey1 + pubkey2 = priv_to_pub(privkey1 + privkey2)

    >>> add_pubkeys("02626d64aaed6eafc082a32f01c35a8909a69226031175d2cf3e7498f3b13796ed","02e4b2672b7db8619c1847076012719afb4baa61e227c33555555e8a84e00395e8",False)
    '041a340d9ffa6f2f5efcac45c9c281e60998e64d72866ed4b429b1fc0a64d46a18c13b5f1cc53583f727cbcee242ba1bca5ec8ef275c175a17c0b8688fa648891f'
    """

    try:
        pubkey1 = hexlify_(unhexlify_(pubkey1))
        pubkey1Int = int(pubkey1,16)
        pubkey1Int = ""
    except:
        raise TypeError("Public key 1 input is not hex or is odd length.")
    if len(pubkey1) == 130:
        if pubkey1[:2] != '04':
            raise TypeError("Public key 1 length is 130 chars but pubkey1[:2] is not '04'.")
    elif len(pubkey1) == 66:
        if pubkey1[:2] != '02' and pubkey1[:2] != '03':
            raise TypeError("Public key 1 length is 66 chars but pubkey1[:2] is not '02' or '03'.")
    else:
        raise TypeError("Public key 1 input hex does not appear to be a public key. Please check input for errors.")
    try:
        pubkey2 = hexlify_(unhexlify_(pubkey2))
        pubkey2Int = int(pubkey2,16)
        pubkey2Int = ""
    except:
        raise TypeError("Public key 2 input is not hex or is odd length.")
    if len(pubkey2) == 130:
        if pubkey2[:2] != '04':
            raise TypeError("Public key 2 length is 130 chars but pubkey2[:2] is not '04'.")
    elif len(pubkey2) == 66:
        if pubkey2[:2] != '02' and pubkey2[:2] != '03':
            raise TypeError("Public key 2 length is 66 chars but pubkey2[:2] is not '02' or '03'.")
    else:
        raise TypeError("Public key 2 input hex does not appear to be a public key. Please check input for errors.")
    if len(pubkey1) == 66:
        pubkey1 = uncompress_pubkey(pubkey1)
    if len(pubkey2) == 66:
        pubkey2 = uncompress_pubkey(pubkey2)
    pub1Xint, pub1Yint = int(pubkey1[2:-64],16), int(pubkey1[-64:],16)
    pub2Xint, pub2Yint = int(pubkey2[2:-64],16), int(pubkey2[-64:],16)
    outX, outY = ec_add(pub1Xint,pub1Yint,pub2Xint,pub2Yint)
    outX, outY = hexlify_(outX,64), hexlify_(outY,64)
    if outputCompressed:
        return compress_pub_key(str("04") + outX + outY)
    else:
        return str("04") + outX + outY

def pubkey_to_address(pubKey,versionbyte='00'):
    """
    Convert public key into arbitrary altcoin address string.  P2SH redeem
    scripts can also be input and you just set the version byte to '05'.
    Actually, any hex can be input.  This just gets the hash160() of the
    input, prepends the version byte, then base58-check-encodes it.  This
    method doesn't actually check that the input is of a specific format, only
    whether or not it's valid hex.  The version byte can even be longer than
    two chars.

    >>> pubkey_to_address("0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455")
    '1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T'
    >>> pubkey_to_address("0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71")
    '1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8'
    >>> pubkey_to_address("0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71","47")
    'Vm7pYAqFAog44pBotpa1BymAEEc5HniCCb'
    >>> pubkey_to_address("0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71","30")
    'LWLwtfycqf1uFqypLAug36W4kdgNwrZdNs'
    >>> pubkey_to_address("52410491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8334f864104865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1a986818a7cb624532f062c1d1f8722084861c5c3291ccffef4ec687441048d2455d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896fbab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f322a1863d4621353ae","05")
    '3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC'
    >>> pubkey_to_address(hexlify_("This is terrible."),hexlify_("Don't do this."))
    'B8AV2J78dNNgjdVaznPMUD7Q69khAbdhyethYRXSZNNEBca3Mm7r'
    """

    try:
        pubKey = hexlify_(binascii.unhexlify(pubKey))
        test = int(pubKey,16)
        test = ""
    except:
        raise TypeError("Public key input is not hex or is odd length.")
    try:
        versionbyte = hexlify_(binascii.unhexlify(versionbyte))
        test = int(versionbyte,16)
        test = ""
    except:
        raise TypeError("Version byte input is not hex or is odd length.")
    hash160str = hash160(pubKey)
    hash160withversionbyte = hexlify_(binascii.unhexlify(str(versionbyte) + str(hash160str)))
    return base58_check_and_encode(hash160withversionbyte) 

if __name__ == "__main__":
    import doctest
    doctest.testmod()
