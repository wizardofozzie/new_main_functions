#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Relative import off for doctests
# from ec_math import *
# from hexlify_permissive import *
# from hash_funcs import *
# from base58_hex_conversions import *
# from bitcoin_funcs import *
# from misc_funcs_and_vars import *

from .ec_math import *
from .hexlify_permissive import *
from .hash_funcs import *
from .base58_hex_conversions import *
from .bitcoin_funcs import *
from .misc_funcs_and_vars import *

def sign_hash(hash,privkey,randnonce=str("RFC6979_SHA256"),compresspubkeyout=True):
    """
    Takes much code from WBN:
    https://github.com/wobine/blackboard101/blob/master/EllipticCurvesPart5-TheMagic-SigningAndVerifying.py

    Hash and privkey inputs must be 32 byte (64-char) hex str.  Hash should usually be sha256(data).

    Randnonce value must be "RFC6979_SHA512","RFC6979_SHA256", or 32 byte (64-char) hex str.

    RFC6979 done via importing ecdsa module rather than re-writing everything myself.  If there is an import exception with ecdsa, randnonce is double_sha256(os.urandom(32))

    Outputs tuple of DER sig, public key.

    >>> sign_hash("6753e7fb548e847d6d91e05124f4f67d97603bef361dc21a52c41b7a32e5f25b","9eaa3b8af8312eb8131c305e7ee8ad74d9ba793ed00be37abaec5cf1f93f6df4","26ca80947436419238a43f39f017dce0da19c4e3cb93b2f3dc003b303560de94",True)
    ('30440220184de325afb00cecf94239054a43a3b84636174051847b5f85ef5aec067b19ae0220308ee4efc9038236664842bd28508f8354a41c069a2d34b7ccade99f6ba95c17', '023ab6d400029977e43e6adea21d04db8c7f670817cc13b56359a74d49578ee66e')
    >>> sign_hash("6753e7fb548e847d6d91e05124f4f67d97603bef361dc21a52c41b7a32e5f25b","9eaa3b8af8312eb8131c305e7ee8ad74d9ba793ed00be37abaec5cf1f93f6df4","RFC6979_SHA512",False)
    ('3045022100f589c2227f007162df8b9e046bbaacaec0298f27ee36e0760b598c891b35db960220634b03c831e6ab8cb80357cca7bd8811153a70d0ed8082f7cabf3b112c834670', '043ab6d400029977e43e6adea21d04db8c7f670817cc13b56359a74d49578ee66eaab565f402f372e7f8d9f0d19be06e17b846c64ea43918dd207156dad4071b22')
    >>> sign_hash("6753e7fb548e847d6d91e05124f4f67d97603bef361dc21a52c41b7a32e5f25b","9eaa3b8af8312eb8131c305e7ee8ad74d9ba793ed00be37abaec5cf1f93f6df4","RFC6979_SHA256",True)
    ('30440220282bed2b82d23a120deca8f747f2ac106fabf8ca9fd9ffb797a820b811ca87aa022059f484ca40e3c60aab05d5850509eb3b35f895d4c19acd186e689b1f18117346', '023ab6d400029977e43e6adea21d04db8c7f670817cc13b56359a74d49578ee66e')
    """

    # k = randnonce

    try:
        hash = hexlify_(binascii.unhexlify(hash))
        test2 = int(hash,16)
        test2 = ""
    except:
        raise TypeError("Hash input must be hex")
    try:
        privkey = hexlify_(binascii.unhexlify(privkey))
        test2 = int(privkey,16)
        test2 = ""
    except:
        raise TypeError("Private key input must be hex")
    assert len(hash) == 64
    assert len(privkey) == 64
    if randnonce == "RFC6979_SHA512":
        try: # derive k (aka 'randnonce' in this method) deterministically via RFC6979 using hash algorithm sha512
            import ecdsa
            randnonce = int(ecdsa.rfc6979.generate_k(ecdsa.ecdsa.ellipticcurve.Point(ecdsa.ecdsa.curve_secp256k1,ecdsa.ecdsa._Gx,ecdsa.ecdsa._Gy,ecdsa.ecdsa._r),int(privkey,16),hashlib.sha512,binascii.unhexlify(hash)))
            randnonce = hexlify_(randnonce,64)
        except:
            print("Could not import ecdsa and did not implement RFC6979 for deriving k. k = sha256(sha256(os.urandom(32))).")
            randnonce = double_sha256(binascii.hexlify(os.urandom(32)))
    elif randnonce == "RFC6979_SHA256":
        try: # derive k (aka 'randnonce' in this method) deterministically via RFC6979 using hash algorithm sha256
            import ecdsa
            randnonce = int(ecdsa.rfc6979.generate_k(ecdsa.ecdsa.ellipticcurve.Point(ecdsa.ecdsa.curve_secp256k1,ecdsa.ecdsa._Gx,ecdsa.ecdsa._Gy,ecdsa.ecdsa._r),int(privkey,16),hashlib.sha256,binascii.unhexlify(hash)))
            randnonce = hexlify_(randnonce,64)
        except:
            print("Could not import ecdsa and did not implement RFC6979 for deriving k. k = sha256(sha256(os.urandom(32))).")
            randnonce = double_sha256(binascii.hexlify(os.urandom(32)))
    try:
        randnonce = hexlify_(binascii.unhexlify(randnonce))
        test2 = int(randnonce,16)
        test2 = None
    except:
        raise TypeError("Random number input must be hex")
    assert len(randnonce) == 64
    r = int(str(privkey_to_pubkey(randnonce,True))[2:],16) % N_ORDER
    r = hexlify_(r,64)
    assert len(r) == 64
    s = ((int(hash,16) + (int(r,16) * int(privkey,16))) * (ec_modular_inverse(int(randnonce,16),N_ORDER))) % N_ORDER
    s = hexlify_(s,64)
    assert len(s) == 64
    if int(s,16) > (N_ORDER / 2): # Canonize s to lower value
        s = hexlify_(int(N_ORDER - int(s,16)),64)
        assert len(s) == 64
    if int(r[:2],16) > 127:
        r = str(str("00") + str(r))
        assert len(r) == 66
    if int(s[:2],16) > 127: # Should never happen now that S is always low.
        s = str(str("00") + str(s))
        assert len(s) == 66
    if len(r) == 66:
        r_prefix = str("0221")
    else:
        r_prefix = str("0220")
    if len(s) == 66:
        s_prefix = str("0221")
    else:
        s_prefix = str("0220")
    finalsig = r_prefix + r + s_prefix + s
    len_byte = hexlify_(int(len(finalsig) // 2))
    assert len(len_byte) == 2
    # DER encode. 0x30 = DER sig. next byte is length of all sig data. 0x02 = next value is integer. 0x20 or 0x21 = length of integer hex of next value.  0x00 is prefixed to numbers that start with 0x80 or higher.
    # Look at doctest final output to see it all put together.
    finalsig = str("30") + len_byte + finalsig  # Does NOT include 0x01 SIGHASH_ALL postfix
    return str(finalsig), str(privkey_to_pubkey(privkey,compresspubkeyout))

def verify_sig(hash,DERsig,pubkey):
    """
    Takes much code from WBN:
    https://github.com/wobine/blackboard101/blob/master/EllipticCurvesPart5-TheMagic-SigningAndVerifying.py

    All inputs must be hex str.

    DER sig input should NOT have the 0x01 SIGHASH_ALL byte at the end.

    Outputs True/False

    >>> verify_sig("6753e7fb548e847d6d91e05124f4f67d97603bef361dc21a52c41b7a32e5f25b","30450220184de325afb00cecf94239054a43a3b84636174051847b5f85ef5aec067b19ae022100cf711b1036fc7dc999b7bd42d7af707b660ac0e0151b6b83f32474ed648ce52a","023ab6d400029977e43e6adea21d04db8c7f670817cc13b56359a74d49578ee66e")
    True
    >>> verify_sig("5753e7fb548e847d6d91e05124f4f67d97603bef361dc21a52c41b7a32e5f25b","30450220184de325afb00cecf94239054a43a3b84636174051847b5f85ef5aec067b19ae022100cf711b1036fc7dc999b7bd42d7af707b660ac0e0151b6b83f32474ed648ce52a","023ab6d400029977e43e6adea21d04db8c7f670817cc13b56359a74d49578ee66e")
    False

    # Random actual tx that I don't have the private key for:
    # Tx ID: 60b20eca2285b7ed8b64a1f98277c16fcc205b9e21413d6a72545880d2a3f341
    # First input's sig:
    >>> verify_sig(sha256(sha256("010000000217cbf067a9ad71b2f69ea66a1c94d04cee26f856b5b4bdccaeccb59761419668010000001976a9140a2217742759c9951371083564d94b8b0317528488acffffffff877a5dd62eab9f1fd28739a9ae7c68fcb0f075b2c2ede13cb3acff15d362e2710100000000ffffffff01709cc901000000001976a914ea0fcd06c9c62e590a8975627d0165b514568a5a88ac0000000001000000")),"30440220735364aea32db724e7f0179f48e4ad5a63a3b04f733e82ca5215097a91aa7123022015846041c9564ff96fb269cb5e9b2f24dac003299e5d16d34fb9c699d55825c7","04617f9e26b7f6f776e30cb4aa24ebef9e183caf6da25684862a32446589be20a53c2b37a7283430033bdfd2f31a96edaea88bf9ebf07498476cb34d16b47887ed")
    True
    """

    try:
        hash = hexlify_(binascii.unhexlify(hash))
        test2 = int(hash,16)
        test2 = ""
    except:
        raise TypeError("Hash input must be hex str")
    assert len(hash) == 64
    try:
        pubkey = hexlify_(binascii.unhexlify(pubkey))
        test2 = int(pubkey,16)
        test2 = ""
    except:
        raise TypeError("Public key input must be hex str")
    assert len(pubkey) == 66 or len(pubkey) == 130
    try:
        DERsig = hexlify_(binascii.unhexlify(DERsig))
        test2 = int(hash,16)
        test2 = ""
    except:
        raise TypeError("DER signature input must be hex str")
    assert DERsig[:2] == "30"
    assert len(DERsig) == (int(DERsig[2:4],16) * 2) + 4
    assert DERsig[4:6] == "02"
    len_r = int(DERsig[6:8],16) * 2
    r = int(DERsig[8:(len_r + 8)],16)
    assert DERsig[(len_r + 8):(len_r + 10)] == "02"
    len_s = int(DERsig[(len_r + 10):(len_r + 12)],16) * 2
    assert (len_r + 12 + len_s) == len(DERsig)
    s = int(DERsig[(len_r + 12):(len_r + 12 + len_s)],16)
    assert r < N_ORDER
    w = ec_modular_inverse(s,N_ORDER)
    u1 = privkey_to_pubkey(hexlify_(((int(hash,16) * w) % N_ORDER),64),False)
    assert len(u1) == 130
    u2 = multiply_pub_and_priv(pubkey,hexlify_(((r*w) % N_ORDER),64),False)
    x = int(str(add_pubkeys(u1,u2,True))[2:],16)
    return x==r

if __name__ == "__main__":
    import doctest
    doctest.testmod()
