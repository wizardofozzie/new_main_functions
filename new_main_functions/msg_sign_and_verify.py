#!/usr/bin/env python
# -*- coding: utf-8 -*-
from base64 import b64decode, b64encode

# Relative import off for doctests
# from ec_math import *
# from hexlify_permissive import *
# from hash_funcs import *
# from base58_hex_conversions import *
# from bitcoin_funcs import *
# from misc_funcs_and_vars import *
# from DER_sign_and_verify import *

from .ec_math import *
from .hexlify_permissive import *
from .hash_funcs import *
from .base58_hex_conversions import *
from .bitcoin_funcs import *
from .misc_funcs_and_vars import *
from .DER_sign_and_verify import *

def verify_message(signature, message, addrtype="00"):
    """
    First input is base64 ascii text.  Second is ascii message itself, NOT the hash.  Third optional input is version byte for address type.

    Output is the address corresponding to the signature+message combo, using the version byte to encode it.

    # brainwallet.org example:
    # https://brainwallet.github.io/#sign
    >>> sig = "GzKk3SwFEb71qaMZL0OhyKk6MI/EaofNXeoVafz9A0dALhTGTS5oauY0sOQ6HeKbfrVvHMJeTZf4HqUQNE8NV3k="
    >>> msg = "This is an example of a signed message."
    >>> verify_message(sig,msg,"00")
    '1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN'

    # Coinkite Tor address verification:
    # http://blog.coinkite.com/post/96552768821/signed-by-coinkite-1gpwz-pmu7g
    >>> sig2 = "H+RCnK9nDuEv3/tugNelCqcwkT6eevo1sTdJ+9gmy+rJ5XAihTNfCUiALBCQgp4ybqVmKCON5oQ2mETEZFe5k+I="
    >>> msg2 = "http://gcvqzacplu4veul4.onion"
    >>> verify_message(sig2,msg2)
    '1GPWzXfpN9ht3g7KsSu8eTB92Na5Wpmu7g'
    """

    # message = normalize_input(message)
    sighex = str(hexlify_(b64decode(normalize_input(signature))))
    assert len(sighex) == 130
    r = sighex[2:66]
    s = sighex[66:]
    nV = int(sighex[:2],16)
    compressed = False
    if nV < 27 or nV >= 35:
        return False
    if nV >= 31:
        compressed = True
        nV = nV - 4
    recid = nV - 27
    multiplier = int(N_ORDER*recid) if recid > 1 else 0
    x = (int(r,16) + int(multiplier//2)) % N_ORDER
    alpha = int((pow_mod(x, 3, P_FINITE_FIELD) + 7) % P_FINITE_FIELD)
    beta = int(pow_mod(alpha, (P_FINITE_FIELD+1)//4, P_FINITE_FIELD))
    if beta % 2 != recid:
        y = int((-1*beta) % P_FINITE_FIELD)
    else:
        y = int(beta)
    x = hexlify_(int(x),64)
    assert len(x) == 64
    y = hexlify_(int(y),64)
    assert len(y) == 64
    xy = compress_pubkey(str("04") + str(x) + str(y))
    try:
        e = double_sha256(binascii.hexlify("\x18Bitcoin Signed Message:\n".encode("utf-8") + binascii.unhexlify(varint_bytesize(len(message.encode("utf-8")))) + message.encode("utf-8")))
    except:
        e = double_sha256(binascii.hexlify(bytearray("\x18Bitcoin Signed Message:\n".encode("utf-8") + binascii.unhexlify(varint_bytesize(len(message.encode("utf-8")))) + message.encode("utf-8"),"utf-8")))
    assert len(e) == 64
    minus_e =  hexlify_(int(N_ORDER - int(e,16)),64)
    assert len(minus_e) == 64
    inv_r = hexlify_(int(ec_modular_inverse(int(r,16),N_ORDER)),64)
    assert len(inv_r) == 64
    pubkey = multiply_pub_and_priv(add_pubkeys(multiply_pub_and_priv(xy,s),privkey_to_pubkey(minus_e)),inv_r,False)
    assert len(pubkey) == 130
    if compressed:
        pubkey = str(compress_pubkey(pubkey))
    return pubkey_to_address(pubkey,str(addrtype))

def sign_message(privKey,message,addrtype="00",compressFlag=True,k_value="RFC6979_SHA256"):
    """
    Signs an ascii message with a given private key.  Private key input can be hex, hexstr or WIF str.
    If it is WIF, input addrtype (version byte) and compressFlag values are ignored, and the WIF
    values for those are used.  Output address version byte is WIF version byte minus 0x80.

    k_value can be manually chosen.
    k_value must be "RFC6979_SHA512","RFC6979_SHA256", or 32 byte (64-char) hex str.
    int is not acceptable input for k_value.
    """

    # addrtype (version byte) and compressFlag used to double check with verify_message() before returning output

    # Take private key input of hex or WIF.
    # If input is WIF, WIF input overrides compressFlag and addrtype (version byte) inputs
    try:
        privKey2, isValid = base58_decode(privKey,True,False)
        if (not isValid) or len(str(privKey)) > 53:
            raise Exception("Base58 checksum failed or length too high to be base58 key.")
    except Exception as e:
        try:
            privKey = hexlify_(unhexlify_(privKey))
            assert len(privKey) == 64
        except Exception as f:
            raise Exception("Error with private key input. Exception on base58 decode attempt was: " + str(e) + "\nand exception on attempt to determine if input is hex was: " + str(f))
    else:
        privKey = privKey2
        privKey2 = None
        if len(str(privKey)) == 66:
            compressFlag = False
        elif len(str(privKey)) == 68 and privKey[-2:] == '01':
            compressFlag = True
            privKey = privKey[:-2]
        addrtype = hexlify_(int(int(privKey[:2],16) - int("80",16)),2)
        privKey = str(privKey[2:])
        assert len(privKey) == 64
    # Private key is now in 64 hex chars, and addrtype and compressFlag are set correctly

    # message = normalize_input(message)
    try:
        msghash = double_sha256(binascii.hexlify("\x18Bitcoin Signed Message:\n".encode("utf-8") + binascii.unhexlify(varint_bytesize(len(message.encode("utf-8")))) + message.encode("utf-8")))
    except:
        msghash = double_sha256(binascii.hexlify(bytearray("\x18Bitcoin Signed Message:\n".encode("utf-8") + binascii.unhexlify(varint_bytesize(len(message.encode("utf-8")))) + message.encode("utf-8"),"utf-8")))

    DERsig, pubkey = sign_hash(msghash,privKey,k_value,True)
    pubkey = None
    assert DERsig[:2] == "30"
    assert len(DERsig) == (int(DERsig[2:4],16) * 2) + 4
    assert DERsig[4:6] == "02"
    len_r = int(DERsig[6:8],16) * 2
    r = DERsig[8:(len_r + 8)]
    assert DERsig[(len_r + 8):(len_r + 10)] == "02"
    len_s = int(DERsig[(len_r + 10):(len_r + 12)],16) * 2
    assert (len_r + 12 + len_s) == len(DERsig)
    s = DERsig[(len_r + 12):(len_r + 12 + len_s)]
    assert int(r,16) < N_ORDER
    if len(r) == 66:
        if r[:2] != "00":
            raise Exception("r length is 33 bytes but first byte is not 0x00")
        else:
            r = r[2:]
    if len(s) == 66:
        if s[:2] != "00":
            raise Exception("s length is 33 bytes but first byte is not 0x00")
        else:
            s = s[2:]
    inputaddress = pubkey_to_address(privkey_to_pubkey(privKey,compressFlag),addrtype)
    for i in range(4):
        nV = 27 + i
        if compressFlag:
            nV = nV + 4
        nV_byte = varint_bytesize(int(nV)) # Or should I just be hexlifying the int???? For one byte it doesn't matter...
        finalstr = normalize_input(str(b64encode(binascii.unhexlify(str(nV_byte) + str(r) + str(s)))))
        if verify_message(finalstr,message,addrtype) == inputaddress:
            return str(finalstr)
    raise Exception("Reached end of signature method.")
