#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hexlify_permissive import *

def sha256(inputhex=""):
    """
    sha256 from hashlib, but made to take hex as input and output hex.
    Just ever so slightly easier.  Obviously, this is not meant for
    speed...

    >>> sha256()
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    >>> sha256("e851972d092a0996dc038e8b")
    '47d05694084374eb94ebfe793896215d6bc074b0142405044d8362b28e776be7'
    """

    if inputhex == "":
        return str("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    try:
        test1 = unhexlify_(inputhex)
        test2 = int(inputhex,16)
        test1,test2 = "",""
    except:
        raise TypeError("Input is not hex or is odd length, please fix.")
    try:
        output = hexlify_(hashlib.sha256(unhexlify_(inputhex)).digest())
    except Exception as e:
        raise Exception(str(e))
    assert len(output) == 64
    return str(output)

def double_sha256(hexinput=""):
    """
    Takes hex in and returns hashlib.sha256(hashlib.sha256(unhexlify_(hex)).digest()).hexdigest()

    >>> double_sha256("446f6e277420646f20746869732e9d85971cc02d56cc0440386e626eae0e85018a07")
    '55df695d7fa337ddf65c12284e38d6f8526b5a72fb262161ac79523fed8c8854'
    """
    if hexinput == "":
        return str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
    try:
        output = hexlify_(hashlib.sha256(hashlib.sha256(unhexlify_(hexinput)).digest()).digest())
    except Exception as e:
        raise Exception(str(e))
    assert len(output) == 64
    return str(output)

def ripemd160(inputhex):
    """
    A ripemd function that acts the same as the sha256 function, rather
    than the weird way ripemd works in hashlib.  This differs from sha256
    however in that both the input and output are hex by default.  There's
    just no need to make this into a class object.

    >>> ripemd160("0000686db504e20c792eaa07fe09224a45ff328e24a80072d04d16abc5c2b5d2")
    '875a1c0483aaa0f5d1d1713fd8e180bd106a6f54'
    >>> ripemd160(sha256("02626d64aaed6eafc082a32f01c35a8909a69226031175d2cf3e7498f3b13796ed"))
    '60d576a69bda6b5f240db90d07f61f76322d7743'
    """

    try:
        test1 = hexlify_(binascii.unhexlify(inputhex))
        test2 = int(inputhex,16)
    except:
        if inputhex == '':
            return str("9c1185a5c5e9fc54612808977ee8f548b2258d31")
        else:
            raise TypeError("Input is not hex or is odd length.")
    test1, test2 = "",""
    ripe160 = hashlib.new('ripemd160')
    ripe160.update(binascii.unhexlify(inputhex))
    ripe160.digest()
    output = hexlify_(binascii.unhexlify(ripe160.hexdigest()))
    assert len(output) == 40
    return output

def hash160(inputhex):
    """
    Return ripemd160(sha256()) for given input hex.

    >>> hash160("0459b4baf72f02af2b35d8c2cde59b828f9012478b2104cbfcc14c10e256e8bfbc199a3a7523799e2f8d7cb617e19405949d694f857ca52c41c3b8175d704413b2")
    '3133cb8559c130b1423244130eb659c2ae6cd83d'
    >>> hash160("0259b4baf72f02af2b35d8c2cde59b828f9012478b2104cbfcc14c10e256e8bfbc")
    'ad63fbc960453d37ad1db2fbd1ac27ce6f83c02b'
    >>> hash160(privkey_to_pubkey(sha256(hexlify_("correct horse battery staple")),False))
    'c4c5d791fcb4654a1ef5e03fe0ad3d9c598f9827'
    """

    try:
        inputhex = hexlify_(binascii.unhexlify(inputhex))
        test = int(inputhex,16)
        test = ""
    except:
        if inputhex == '':
            return str("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")
        else:
            raise TypeError("Input is not hex or is odd length.")
    ripe160 = hashlib.new('ripemd160')
    ripe160.update(hashlib.sha256(binascii.unhexlify(inputhex)).digest())
    ripe160.digest()
    output = hexlify_(binascii.unhexlify(ripe160.hexdigest()))
    assert len(output) == 40
    return output

if __name__ == "__main__":
    import doctest
    doctest.testmod()
