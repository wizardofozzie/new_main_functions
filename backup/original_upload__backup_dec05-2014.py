#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function, division, absolute_import, unicode_literals
try:
    from __builtin__ import bytes, str, open, super, range, zip, round, int, pow, object, input
except ImportError:
    pass
try:
    from __builtin__ import raw_input as input
except:
    pass
from codecs import decode
import os
import sys
import unicodedata
import binascii
import hashlib
import hmac

# Much of the following functions taken from James D'Angelo's
# World Bitcoin Network Blackboard series code:
# https://github.com/wobine/blackboard101/blob/master/EllipticCurvesPart5-TheMagic-SigningAndVerifying.py

# secp256k1 curve:  y^2 = x^3 + 7
# secp256k1 elliptic curve is  y^2 = x^3 + A*x^2 + B, with the following parameters:

# P_FINITE_FIELD = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
# P_FINITE_FIELD = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
P_FINITE_FIELD = 115792089237316195423570985008687907853269984665640564039457584007908834671663
# Order of the curve as defined by the generator G
# N_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
N_ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337
A_CURVE = 0 # 0x00
B_CURVE = 7 # 0x07
H_COFACTOR = 1
GENERATOR_POINT_XCOORD = 55066263022277343669578718895168534326250603453777594175500187360389116729240
GENERATOR_POINT_YCOORD = 32670510020758816978083085130507043184471273380659243275938904335757337482424
# GENERATOR_POINT (compressed format) = 0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
# GENERATOR_POINT (uncompressed format) = 0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8


def ec_modular_inverse(a,p=P_FINITE_FIELD):
    """
    Calculate the modular inverse

    # Doctest done this way for Python 2/3 output compatibility.  2 shows the long "L", 3 doesn't.
    # Function output is an int, doctest is converting to string because of the "L" issue.
    # Fuck you, Python 3.  Isn't backwards compatability like the very first rule of updating!?
    >>> x = str(ec_modular_inverse(2521213890399410648018095333325722136449021566908310412768334520696982806641)).replace("L",""); x = x.encode("ascii") if int(sys.version_info.major) == 2 else x; x
    '17465617466841484688650846354295959695753514552349626970717521890536775674935'
    >>> x = str(ec_modular_inverse(-95700528412413679576195283092455617561285633360671739483652140770588235170392)).replace("L",""); x = x.encode("ascii") if int(sys.version_info.major) == 2 else x; x
    '85074060877409777477878269288729801496418474660084822316781824988361036308728'
    """

    lm, hm = 1, 0
    low, high = a % p, p
    while low > 1:
        ratio = high // low
        nm, new = hm - lm*ratio, high - low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % p

def ec_add(xp,yp,xq,yq):
    """
    Add two points (e.g. public keys)

    # Doctest done this way for Python 2/3 output compatibility.  2 shows the long "L", 3 doesn't.
    # Function output is a tuple of two ints, doctest is converting to string.
    # Fuck you, Python 3.
    >>> x = str(ec_add(4938373901174265576094805690384936437621390742743114714534166734031749709952,23406007515733211420427986631155727216565925582529100160361434981966318828999,11029270422249989266356636372380040023432092195222839243672437607748020962878,12338920660869481789439141094019604918037726829679018934712977981859756778348)).replace("L",""); x = x.encode("ascii") if int(sys.version_info.major) == 2 else x; x
    '(83336094426407305185582932726071265758876028986498851406936393497302545717601, 71857134501436534997244054415723847888276629084374532235863885413095164252131)'
    """

    m = ((yq-yp) * ec_modular_inverse(xq-xp,P_FINITE_FIELD)) % P_FINITE_FIELD
    xr = (m*m-xp-xq) % P_FINITE_FIELD
    yr = (m*(xp-xr)-yp) % P_FINITE_FIELD
    return xr, yr

def ec_double(xp,yp):
    """
    EC double and add.

    # Doctest done this way for Python 2/3 output compatibility.  2 shows the long "L", 3 doesn't.
    # Function output is a tuple of two ints, doctest is converting to string.
    # Fuck you, Python 3.
    >>> x = str(ec_double(int("25db0d7c0937fa36e90eb7250f7acdaac4a87a4a6dfddf4e83ddc8ad7a2706a4",16),int("5a49808395b6076121d460f4e2bf6870126a8f9bc8fea89cf23cd5369ccc40a2",16))).replace("L",""); x = x.encode("ascii") if int(sys.version_info.major) == 2 else x; x
    '(72311113040667355501201059093433510680042205181920994715815687665050367873657, 81202695815007557875587128276299271839897857009219307151962560322569452526782)'
    """

    lam_numerator = 3*xp*xp + A_CURVE
    lam_denominator = 2*yp
    lam = (lam_numerator * ec_modular_inverse(lam_denominator,P_FINITE_FIELD)) % P_FINITE_FIELD
    xr = (lam**2 - 2*xp) % P_FINITE_FIELD
    yr = (lam*(xp-xr) - yp) % P_FINITE_FIELD
    return xr, yr

def ec_multiply(xs,ys,scalar):
    """
    Multiply a point by an integer scalar.

    # Doctest done this way for Python 2/3 output compatibility.  2 shows the long "L", 3 doesn't.
    # Function output is a tuple of two ints, doctest is converting to string.
    # Fuck you, Python 3.
    >>> x = str(ec_multiply(GENERATOR_POINT_XCOORD,GENERATOR_POINT_YCOORD,int("f0f8320854b2e2de419eedb944712c637f7d6e64575d72e418ddd5dbe2d17e5f",16))).replace("L",""); x = x.encode("ascii") if int(sys.version_info.major) == 2 else x; x
    '(31820500337434663034378937821014238946693466936619003016246787278539969552979, 66732635296424336282461257473650291615494485896357730900289668032470013600761)'
    >>> x = str(ec_multiply(int("efd664a8ba051501cbe1481256b78e68258fa82d4688e735afef4ecedf57d54e",16),int("aa4f10521ab13f159cdcd2ef3f8d07dfb006c3475b25802cdab981bd2208e4b2",16),int("8de2c4d3b801f3a4631dc4f0552ceafcd4ec2dfa5de63e01a16f26e5a31fe182",16))).replace("L",""); x = x.encode("ascii") if int(sys.version_info.major) == 2 else x; x
    '(111195224946782627442102896291867110669355049951187464408301520676061840582303, 33198247759150618685238112745670350342898303048531376301548958234322222588356)'
    """

    if scalar == 0 or scalar >= N_ORDER:
        raise Exception("Scalar input not between 0 and N-1.")
    scalar_bin = str(bin(scalar)).lstrip('0b')
    Qx,Qy=xs,ys
    for i in range (1, len(scalar_bin)):
        Qx, Qy = ec_double(Qx,Qy)
        if scalar_bin[i] == '1':
            Qx,Qy=ec_add(Qx,Qy,xs,ys)
    return Qx, Qy

# End WBN code

def hexlify_(datainput,zfill_=0):
    """
    Hexlifies data and ints, and adds a zfill if necessary.
    If data is already hex, returns the input back, formatted and zfilled.

    ***WARNING***
    This means that if you have a string which happens to be only hex chars,
    it will NOT be hexlified properly.  It will be returned as itself.
    hexlify_("a") returns "0a".  hexlify_("abcdef") returns "abcdef"
    hexlify_(0) returns "00".  hexlify_("00") returns "00"
    (Note in doctest about hexlify_("0") returning "30")
    ***END WARNING***

    It's messy because damned Python 3 gives different outputs and handles
    strings differently than Python 2.  WTF Python 3.

    Have I mentioned how much I hate Python 3?
    WHY U NO BACKWARDS COMPATIBLE

    The hex char 0x30 which represents int(0) also caused problems in Python 3,
    which is why you see that around.  Sorry for my messy code, but it does
    actually work very well, and as expected, even with edge cases.

    >>> hexlify_("")
    ''
    >>> hexlify_("zer0")
    '7a657230'
    >>> hexlify_(0)
    '00'
    >>> hexlify_(00000000)
    '00'
    >>> hexlify_("0") # There was no way around this since unhexlify("30") is exactly equal to str("0")
    '30'
    >>> hexlify_("00")
    '00'
    >>> hexlify_("00000000")
    '00000000'
    >>> hexlify_(12345678)
    'bc614e'
    >>> hexlify_(1234567890123456789012345678901234567890123456789012345678901234)
    '030046030f26f462d7ac21a27eb9d53fff233c7acd12d87e96aff2'
    >>> hexlify_(348)
    '015c'
    >>> hexlify_(hex(348))
    '015c'
    >>> hexlify_("ab0cde8d8a8fee")
    'ab0cde8d8a8fee'
    >>> hexlify_("b0cde8d8a8fee")
    '0b0cde8d8a8fee'
    >>> hexlify_("b0cde8d8a8fee",32)
    '0000000000000000000b0cde8d8a8fee'
    >>> hexlify_("This is a test.")
    '54686973206973206120746573742e'
    >>> hexlify_("This is also a test.",64)
    '0000000000000000000000005468697320697320616c736f206120746573742e'
    >>> hexlify_("30")
    '30'
    >>> hexlify_(binascii.unhexlify("30"))
    '30'
    >>> hexlify_(binascii.unhexlify("2a83af8e8edee9caeb3f32ca4683eca58c50faa06a"))
    '2a83af8e8edee9caeb3f32ca4683eca58c50faa06a'
    >>> hexlify_("6b4e6c1fe36504e12e6d9716f74250ecb6fefb2a83af8e8edee9caeb3f32ca4683eca58c50faa06afc40a15fdc4c")
    '6b4e6c1fe36504e12e6d9716f74250ecb6fefb2a83af8e8edee9caeb3f32ca4683eca58c50faa06afc40a15fdc4c'
    """

    isHex = True
    output = ""
    try:
        if binascii.hexlify(datainput) == '30':
            output = str("30")
    except:
        try:
            if len(str(datainput)) == 1 and str(datainput) == "0" and 'int' not in str(type(datainput)):
                output = str("30")
        except:
            pass
    if 'unicode' in str(type(datainput)) and output != str("30"):
        datainput = str(datainput)
        try:
            datainput = unicode(datainput)
        except:
            pass
        datainput = unicodedata.normalize('NFC',datainput)
        datainput = str(datainput)
    if 'str' in str(type(datainput)) and output != str("30"):
        try:
            x = binascii.unhexlify(datainput)
        except:
            try:
                if str("LL") in str(datainput[-2:]).upper():
                    output = binascii.hexlify(datainput)
                else:
                    teststr = datainput.lstrip("0x").rstrip("L")
                    for char in teststr:
                        if char not in '0123456789abcdefABCDEF':
                            isHex = False
                            break
                    if isHex:
                        output = datainput.lstrip("0x").rstrip("L")
                    else:
                        try:
                            output = binascii.hexlify(datainput)
                        except:
                            output = binascii.hexlify(datainput.encode('utf-8'))
            except:
                output = binascii.hexlify(datainput)
        else:
            output = binascii.hexlify(x)
    elif (('int' not in str(type(datainput))) and ('long' not in str(type(datainput))) and (str(datainput) == str('') or not datainput)) and output != str("30"):
        output = str('').zfill(zfill_)
        if output == str(''):
            return str('')
    elif ('int' in str(type(datainput)) or 'long' in str(type(datainput))) and output != str("30"):
        try:
            if int(datainput) == 0:
                output = "00"
            else:
                x = binascii.unhexlify(hex(datainput))
        except:
            output = '0' + str(hex(datainput)).replace('0x','').replace('L','')
            if len(output) % 2 and output[:1] == '0':
                output = output[1:]
        else:
            try:
                output = binascii.hexlify(x)
            except:
                pass
    elif output != str("30"):
        output = binascii.hexlify(datainput)
    try:
        output = str(binascii.hexlify(binascii.unhexlify(output)))
    except Exception as e:
        if "Odd-length string" in str(e):
            output = "0" + output.replace("0x","").replace("L","")
            output = str(binascii.hexlify(binascii.unhexlify(output)))
        else:
            raise Exception(str(e))
    output = "z" + str(output)
    output = str(output).replace('L','').replace('0x','').replace("'",'').replace('z','')
    if int(sys.version_info.major) == 3:
        output = "z" + output
        output = output[2:].replace("'",'').replace("'",'')
        output = str(output)
    output = output.zfill(zfill_)
    if len(output) % 2:
        output = '0' + output
    output = output.lower()
    return str(output)

def unhexlify_(datainput):
    """
    Returns byte array (raw data) from hex.
    Tries to fix common input errors.  e.g. prepends '0' if necessary, converts ints to hex then unhexlifies, etc.

    # Doctest done this way for Python 2/3 output compatibility
    # If I haven't already made it clear, god damn I hate Python 3.
    >>> bytearray(unhexlify_("aabbaabb"))
    bytearray(b'\\xaa\\xbb\\xaa\\xbb')
    >>> bytearray(unhexlify_("abbaabb"))
    bytearray(b'\\n\\xbb\\xaa\\xbb')
    >>> bytearray(unhexlify_(565645236754))
    bytearray(b'\\x83\\xb3\\x15Z\\x12')
    >>> bytearray(unhexlify_(565645236754215376762318132587025307653276093712076))
    bytearray(b'\\x01\\x83\\x07\\xb9\\xa6\\xd7I\\xef\\xcf\\xb3\\xb6j\\xe4\\xbe&\\xde\\xd0\\xd8\\xd11\\x06\\xcc')
    >>> unhexlify_("abbaabb") == unhexlify_("0abbaabb")
    True
    >>> unhexlify_("aabbaabb") == unhexlify_("0xaabbaabb")
    True
    >>> unhexlify_("0xabbaabb") == unhexlify_("0x0abbaabb")
    True
    """

    try:
        return binascii.unhexlify(datainput)
    except Exception as e:
        if "Odd-length string" in str(e):
            datainput = datainput.replace("0x","").replace("L","")
            if len(datainput) % 2:
                datainput = "0" + datainput
            return binascii.unhexlify(datainput)
        elif "must be string or buffer, not int" in str(e) or "not <class 'int'>" in str(e) or "must be string or buffer, not long" in str(e) or "not <class 'long'>" in str(e):
            # hexlify_ turns int/long into hex
            return binascii.unhexlify(hexlify_(datainput))
        elif "Non-hexadecimal digit found" in str(e):
            try:
                datainput = datainput.replace("0x","").replace("L","")
                if len(datainput) % 2:
                    datainput = "0" + datainput
                return binascii.unhexlify(datainput)
            except:
                raise Exception(str(e))
        else:
            raise Exception(str(e))

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

def pow_mod(x,y,z):
    """
    Modular exponentiation

    Code taken from:
    https://bitcointalk.org/index.php?topic=644919.msg7205689#msg7205689

    # Doctest done this way for Python 2/3 output compatibility.  2 shows the long "L", 3 doesn't.
    # Function output is an int, doctest is converting to string.
    # Go fist yourself Python 3.
    >>> x = str(pow_mod(49037091911445311960505094255833255054007297934908240385782191104413347423659,3,P_FINITE_FIELD)).replace("L",""); x = x.encode("ascii") if int(sys.version_info.major) == 2 else x; x
    '108407473609415631692389176799183067844089343123321095921775096357884899238351'
    """

    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

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

def base58_check(payload,prefix='',postfix=''):
    """
    Returns the 4 byte checksum that is done prior to base58 encoding a key.
    Input must be hex.

    >>> base58_check("763dd13ba59f839b042746faf2edb669e215e6e2","00")
    '496852f3'
    >>> base58_check("00763dd13ba59f839b042746faf2edb669e215e6e2")
    '496852f3'
    >>> base58_check("d13ba59f839b042746faf2edb6","00763d","69e215e6e2")
    '496852f3'
    """

    try:
        payload = hexlify_(binascii.unhexlify(payload))
        test1 = int(payload,16)
        test1 = ""
    except:
        raise TypeError("First input is not hex or is odd length.")
    if prefix != '':
        try:
            prefix = hexlify_(binascii.unhexlify(prefix))
            test1 = int(prefix,16)
            test1 = ""
        except:
            raise TypeError("Second input is not hex or is odd length.")
    else:
        prefix = str("")
    if postfix != '':
        try:
            postfix = hexlify_(binascii.unhexlify(postfix))
            test1 = int(postfix,16)
            test1 = ""
        except:
            raise TypeError("Third input is not hex or is odd length.")
    else:
        postfix = str("")
    finalHash = double_sha256(prefix + payload + postfix)
    assert len(finalHash) == 64
    return str(finalHash[:8])

def base58_encode(a,version='',postfix=''):
    """
    Base58 encode input, without checksum.  Input must be hex.

    Mostly ripped from:
    https://github.com/jgarzik/python-bitcoinlib/blob/master/bitcoin/base58.py

    >>> base58_encode("00763dd13ba59f839b042746faf2edb669e215e6e2496852f3")
    '1BnCnn9eGv85xBHLyNqRUn9fN5TF1T5t9x'
    >>> base58_encode("00000000763dd13ba59f839b042746faf2edb669e215e6e2496852f3")
    '1111BnCnn9eGv85xBHLyNqRUn9fN5TF1T5t9x'
    >>> base58_encode("763dd13ba59f839b042746faf2edb669e215e6e2","00","496852f3")
    '1BnCnn9eGv85xBHLyNqRUn9fN5TF1T5t9x'
    >>> base58_encode("00763dd13ba59f839b042746faf2edb669e215e6e2","","496852f3")
    '1BnCnn9eGv85xBHLyNqRUn9fN5TF1T5t9x'
    >>> base58_encode("c210b04ec8eb255b")
    'ZTgBBhesSn6'
    >>> base58_encode("36fb72694f9a9873fdbd41f0f2935fdb644ed668355bc7fb697e9c6723b1209b")
    '4hdQ1CEndPRAdXdqeegtnyGJiWngpyFdPckavxtFRUPL'
    """

    try:
        a = hexlify_(binascii.unhexlify(a))
        test1 = int(a,16)
        test1 = ""
    except:
            raise TypeError("First input is not hex.")
    if version != '':
        try:
            version = hexlify_(binascii.unhexlify(version))
            test1 = int(version,16)
            test1 = ""
        except:
            raise TypeError("Second input is not hex.")
    else:
        version = str("")
    if postfix != '':
        try:
            postfix = hexlify_(binascii.unhexlify(postfix))
            test1 = int(postfix,16)
            test1 = ""
        except:
            raise TypeError("Third input is not hex.")
    else:
        postfix = str("")
    b = version + a + postfix
    b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n1 = int(b,16)
    res = []
    while n1 > 0:
        n1, r = divmod(n1,58)
        res.append(b58_digits[r])
    res = ''.join(res[::-1])
    pad = 0
    assert not (len(b) % 2)
    for i in range(int(len(b) // 2)):
        j = 2*i
        teststr = b[j] + b[j+1]
        if teststr == '00':
            pad += 1
        else:
            break
    return str(b58_digits[0] * pad + res)

def base58_decode(s,doEval=True,returnWithChecksum=True):
    """
    Decode base58 string.  If doEval is True, the output is a tuple with
    the decoded hex and a True/False bool indicating whether the decoded
    checksum verified.  If doEval is False, the output is just the decoded
    hex.  If returnWithChecksum is False, the least significant 8 chars are
    cut off, otherwise the entire decode is returned.

    Mostly ripped from:
    https://github.com/jgarzik/python-bitcoinlib/blob/master/bitcoin/base58.py

    >>> base58_decode("1111BnCnn9eGv85xBHLyNqRUn9fN5TF1T5t9x")
    ('00000000763dd13ba59f839b042746faf2edb669e215e6e2496852f3', False)
    >>> base58_decode("1111BnCnn9eGv85xBHLyNqRUn9fN5TF1T5t9x",False,False)
    '00000000763dd13ba59f839b042746faf2edb669e215e6e2'
    >>> base58_decode("4hdQ1CEndPRAdXdqeegtnyGJiWngpyFdPckavxtFRUPL",False)
    '36fb72694f9a9873fdbd41f0f2935fdb644ed668355bc7fb697e9c6723b1209b'
    >>> base58_decode("1BnCnn9eGv85xBHLyNqRUn9fN5TF1T5t9x",True,False)
    ('00763dd13ba59f839b042746faf2edb669e215e6e2', True)
    """

    s = str(s)
    if not s or s == '':
        if doEval:
            return '', False
        else:
            return ''

    b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n1 = 0
    for c in s:
        n1 *= 58
        if c not in b58_digits:
            raise Exception('Decode Error:  Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n1 += digit
    h = '%x' % n1
    if len(h) % 2:
        h = '0' + h
    res = str(h)
    pad = 0
    for c in s:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    outputStrWithChecksum = '00' * pad + res
    outputStrNoCheck = outputStrWithChecksum[:-8]
    outputLength = len(outputStrWithChecksum) - 8
    checksum = outputStrWithChecksum[outputLength:]
    if returnWithChecksum:
        outputStr = unhexlify_(str(outputStrWithChecksum))
    else:
        outputStr = unhexlify_(str(outputStrNoCheck))
    if doEval:
        return hexlify_(outputStr), base58_check(outputStrNoCheck) == checksum
    else:
        return hexlify_(outputStr)

def base58_check_and_encode(a):
    """
    Perform base58 check and then encode input and checksum.
    Input must be hex.

    >>> base58_check_and_encode("763dd13ba59f839b042746faf2edb669e215e6e2")
    'BnCnn9eGv85xBHLyNqRUn9fN5TF3rmBYw'
    >>> base58_check_and_encode("00763dd13ba59f839b042746faf2edb669e215e6e2")
    '1BnCnn9eGv85xBHLyNqRUn9fN5TF1T5t9x'
    >>> base58_check_and_encode("000000763dd13ba59f839b042746faf2edb669e215e6e2")
    '111BnCnn9eGv85xBHLyNqRUn9fN5TF61w7JE'
    """

    try:
        a = hexlify_(binascii.unhexlify(a))
        test2 = int(a,16)
        test2 = ""
    except:
        raise TypeError("Input is not hex or is odd length.")
    return str(base58_encode(a,'',base58_check(a)))

def privkey_to_hexstr(privkey_unknownformat):
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

def reverse_bytes(hexstrinput):
    """
    Reverses bytes of a hex string input.

    >>> reverse_bytes("6896416197b5ccaeccbdb4b556f826ee4cd0941c6aa69ef6b271ada967f0cb17")
    '17cbf067a9ad71b2f69ea66a1c94d04cee26f856b5b4bdccaeccb59761419668'
    >>> reverse_bytes("0x896416197b5ccaeccbdb4b556f826ee4cd0941c6aa69ef6b271ada967f0cb17L")
    '17cbf067a9ad71b2f69ea66a1c94d04cee26f856b5b4bdccaeccb59761419608'
    """

    try:
        hexstrinput = hexlify_(unhexlify_(hexstrinput))
        test2 = int(hexstrinput,16)
        test2 = ""
    except:
        raise TypeError("Input must be hex")
    assert not len(hexstrinput) % 2
    output = str("")
    for i in range(int(len(hexstrinput) // 2)):
        j = i*2
        if j == 0:
            output = output + hexstrinput[-1*(j+2):]
        else:
            output = output + hexstrinput[-1*(j+2):-1*(j)]
    return str(output)

def sign_hash(hash,privkey,randnonce=str("RFC6979_SHA512"),compresspubkeyout=True):
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

    # randnonce = k

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
    if int(s[:2],16) > 127:
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

class Bip39EngClass(object):
    """
    Simple object to hold information about a BIP39 English wordlist.

    >>> doctester = Bip39EngClass("turtle front uncle idea crush write shrug there lottery flower risk shell")
    >>> doctester.hex
    'eaebabb2383351fd31d703840b32e9e2'
    >>> doctester.bip32seed
    '4ef6e8484a846392f996b15283906b73be4ec100859ce68689d5a0fad7f761745b86d70ea5f5c43e4cc93ce4b82b3d9aeed7f85d503fac00b10ebbc150399100'
    >>> doctester.setPBKDF2password("TREZOR")
    >>> doctester.bip32seed
    'bdfb76a0759f301b0b899a1e3985227e53b3f51e67e3f2a65363caedf3e32fde42a66c404f18d7b05818c95ef3ca1e5146646856c461c073169467511680876c'
    >>> str(Bip32Key(Bip39EngClass("legal winner thank year wave sausage worth useful legal winner thank yellow","TREZOR").bip32seed))
    'xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq'
    >>> Bip39EngClass.hex_to_wordlist("00000000000000000000000000000000")
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    >>> Bip39EngClass.wordlist_to_hex("board flee heavy tunnel powder denial science ski answer betray cargo cat")
    '18ab19a9f54a9274f03e5209a2ac8a91'
    >>> Bip39EngClass.wordlist_to_hex("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    '00000000000000000000000000000000'
    """

    # https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    BIP0039_ENG_WORDLIST = [
        'abandon','ability','able','about','above','absent','absorb',
        'abstract','absurd','abuse','access','accident','account',
        'accuse','achieve','acid','acoustic','acquire','across','act',
        'action','actor','actress','actual','adapt','add','addict',
        'address','adjust','admit','adult','advance','advice',
        'aerobic','affair','afford','afraid','again','age','agent',
        'agree','ahead','aim','air','airport','aisle','alarm','album',
        'alcohol','alert','alien','all','alley','allow','almost',
        'alone','alpha','already','also','alter','always','amateur',
        'amazing','among','amount','amused','analyst','anchor',
        'ancient','anger','angle','angry','animal','ankle','announce',
        'annual','another','answer','antenna','antique','anxiety',
        'any','apart','apology','appear','apple','approve','april',
        'arch','arctic','area','arena','argue','arm','armed','armor',
        'army','around','arrange','arrest','arrive','arrow','art',
        'artefact','artist','artwork','ask','aspect','assault',
        'asset','assist','assume','asthma','athlete','atom','attack',
        'attend','attitude','attract','auction','audit','august',
        'aunt','author','auto','autumn','average','avocado','avoid',
        'awake','aware','away','awesome','awful','awkward','axis',
        'baby','bachelor','bacon','badge','bag','balance','balcony',
        'ball','bamboo','banana','banner','bar','barely','bargain',
        'barrel','base','basic','basket','battle','beach','bean',
        'beauty','because','become','beef','before','begin','behave',
        'behind','believe','below','belt','bench','benefit','best',
        'betray','better','between','beyond','bicycle','bid','bike',
        'bind','biology','bird','birth','bitter','black','blade',
        'blame','blanket','blast','bleak','bless','blind','blood',
        'blossom','blouse','blue','blur','blush','board','boat',
        'body','boil','bomb','bone','bonus','book','boost','border',
        'boring','borrow','boss','bottom','bounce','box','boy',
        'bracket','brain','brand','brass','brave','bread','breeze',
        'brick','bridge','brief','bright','bring','brisk','broccoli',
        'broken','bronze','broom','brother','brown','brush','bubble',
        'buddy','budget','buffalo','build','bulb','bulk','bullet',
        'bundle','bunker','burden','burger','burst','bus','business',
        'busy','butter','buyer','buzz','cabbage','cabin','cable',
        'cactus','cage','cake','call','calm','camera','camp','can',
        'canal','cancel','candy','cannon','canoe','canvas','canyon',
        'capable','capital','captain','car','carbon','card','cargo',
        'carpet','carry','cart','case','cash','casino','castle',
        'casual','cat','catalog','catch','category','cattle','caught',
        'cause','caution','cave','ceiling','celery','cement','census',
        'century','cereal','certain','chair','chalk','champion',
        'change','chaos','chapter','charge','chase','chat','cheap',
        'check','cheese','chef','cherry','chest','chicken','chief',
        'child','chimney','choice','choose','chronic','chuckle',
        'chunk','churn','cigar','cinnamon','circle','citizen','city',
        'civil','claim','clap','clarify','claw','clay','clean',
        'clerk','clever','click','client','cliff','climb','clinic',
        'clip','clock','clog','close','cloth','cloud','clown','club',
        'clump','cluster','clutch','coach','coast','coconut','code',
        'coffee','coil','coin','collect','color','column','combine',
        'come','comfort','comic','common','company','concert',
        'conduct','confirm','congress','connect','consider','control',
        'convince','cook','cool','copper','copy','coral','core',
        'corn','correct','cost','cotton','couch','country','couple',
        'course','cousin','cover','coyote','crack','cradle','craft',
        'cram','crane','crash','crater','crawl','crazy','cream',
        'credit','creek','crew','cricket','crime','crisp','critic',
        'crop','cross','crouch','crowd','crucial','cruel','cruise',
        'crumble','crunch','crush','cry','crystal','cube','culture',
        'cup','cupboard','curious','current','curtain','curve',
        'cushion','custom','cute','cycle','dad','damage','damp',
        'dance','danger','daring','dash','daughter','dawn','day',
        'deal','debate','debris','decade','december','decide',
        'decline','decorate','decrease','deer','defense','define',
        'defy','degree','delay','deliver','demand','demise','denial',
        'dentist','deny','depart','depend','deposit','depth','deputy',
        'derive','describe','desert','design','desk','despair',
        'destroy','detail','detect','develop','device','devote',
        'diagram','dial','diamond','diary','dice','diesel','diet',
        'differ','digital','dignity','dilemma','dinner','dinosaur',
        'direct','dirt','disagree','discover','disease','dish',
        'dismiss','disorder','display','distance','divert','divide',
        'divorce','dizzy','doctor','document','dog','doll','dolphin',
        'domain','donate','donkey','donor','door','dose','double',
        'dove','draft','dragon','drama','drastic','draw','dream',
        'dress','drift','drill','drink','drip','drive','drop','drum',
        'dry','duck','dumb','dune','during','dust','dutch','duty',
        'dwarf','dynamic','eager','eagle','early','earn','earth',
        'easily','east','easy','echo','ecology','economy','edge',
        'edit','educate','effort','egg','eight','either','elbow',
        'elder','electric','elegant','element','elephant','elevator',
        'elite','else','embark','embody','embrace','emerge','emotion',
        'employ','empower','empty','enable','enact','end','endless',
        'endorse','enemy','energy','enforce','engage','engine',
        'enhance','enjoy','enlist','enough','enrich','enroll',
        'ensure','enter','entire','entry','envelope','episode',
        'equal','equip','era','erase','erode','erosion','error',
        'erupt','escape','essay','essence','estate','eternal',
        'ethics','evidence','evil','evoke','evolve','exact','example',
        'excess','exchange','excite','exclude','excuse','execute',
        'exercise','exhaust','exhibit','exile','exist','exit',
        'exotic','expand','expect','expire','explain','expose',
        'express','extend','extra','eye','eyebrow','fabric','face',
        'faculty','fade','faint','faith','fall','false','fame',
        'family','famous','fan','fancy','fantasy','farm','fashion',
        'fat','fatal','father','fatigue','fault','favorite','feature',
        'february','federal','fee','feed','feel','female','fence',
        'festival','fetch','fever','few','fiber','fiction','field',
        'figure','file','film','filter','final','find','fine',
        'finger','finish','fire','firm','first','fiscal','fish','fit',
        'fitness','fix','flag','flame','flash','flat','flavor','flee',
        'flight','flip','float','flock','floor','flower','fluid',
        'flush','fly','foam','focus','fog','foil','fold','follow',
        'food','foot','force','forest','forget','fork','fortune',
        'forum','forward','fossil','foster','found','fox','fragile',
        'frame','frequent','fresh','friend','fringe','frog','front',
        'frost','frown','frozen','fruit','fuel','fun','funny',
        'furnace','fury','future','gadget','gain','galaxy','gallery',
        'game','gap','garage','garbage','garden','garlic','garment',
        'gas','gasp','gate','gather','gauge','gaze','general',
        'genius','genre','gentle','genuine','gesture','ghost','giant',
        'gift','giggle','ginger','giraffe','girl','give','glad',
        'glance','glare','glass','glide','glimpse','globe','gloom',
        'glory','glove','glow','glue','goat','goddess','gold','good',
        'goose','gorilla','gospel','gossip','govern','gown','grab',
        'grace','grain','grant','grape','grass','gravity','great',
        'green','grid','grief','grit','grocery','group','grow',
        'grunt','guard','guess','guide','guilt','guitar','gun','gym',
        'habit','hair','half','hammer','hamster','hand','happy',
        'harbor','hard','harsh','harvest','hat','have','hawk',
        'hazard','head','health','heart','heavy','hedgehog','height',
        'hello','helmet','help','hen','hero','hidden','high','hill',
        'hint','hip','hire','history','hobby','hockey','hold','hole',
        'holiday','hollow','home','honey','hood','hope','horn',
        'horror','horse','hospital','host','hotel','hour','hover',
        'hub','huge','human','humble','humor','hundred','hungry',
        'hunt','hurdle','hurry','hurt','husband','hybrid','ice',
        'icon','idea','identify','idle','ignore','ill','illegal',
        'illness','image','imitate','immense','immune','impact',
        'impose','improve','impulse','inch','include','income',
        'increase','index','indicate','indoor','industry','infant',
        'inflict','inform','inhale','inherit','initial','inject',
        'injury','inmate','inner','innocent','input','inquiry',
        'insane','insect','inside','inspire','install','intact',
        'interest','into','invest','invite','involve','iron','island',
        'isolate','issue','item','ivory','jacket','jaguar','jar',
        'jazz','jealous','jeans','jelly','jewel','job','join','joke',
        'journey','joy','judge','juice','jump','jungle','junior',
        'junk','just','kangaroo','keen','keep','ketchup','key','kick',
        'kid','kidney','kind','kingdom','kiss','kit','kitchen','kite',
        'kitten','kiwi','knee','knife','knock','know','lab','label',
        'labor','ladder','lady','lake','lamp','language','laptop',
        'large','later','latin','laugh','laundry','lava','law','lawn',
        'lawsuit','layer','lazy','leader','leaf','learn','leave',
        'lecture','left','leg','legal','legend','leisure','lemon',
        'lend','length','lens','leopard','lesson','letter','level',
        'liar','liberty','library','license','life','lift','light',
        'like','limb','limit','link','lion','liquid','list','little',
        'live','lizard','load','loan','lobster','local','lock',
        'logic','lonely','long','loop','lottery','loud','lounge',
        'love','loyal','lucky','luggage','lumber','lunar','lunch',
        'luxury','lyrics','machine','mad','magic','magnet','maid',
        'mail','main','major','make','mammal','man','manage',
        'mandate','mango','mansion','manual','maple','marble','march',
        'margin','marine','market','marriage','mask','mass','master',
        'match','material','math','matrix','matter','maximum','maze',
        'meadow','mean','measure','meat','mechanic','medal','media',
        'melody','melt','member','memory','mention','menu','mercy',
        'merge','merit','merry','mesh','message','metal','method',
        'middle','midnight','milk','million','mimic','mind','minimum',
        'minor','minute','miracle','mirror','misery','miss','mistake',
        'mix','mixed','mixture','mobile','model','modify','mom',
        'moment','monitor','monkey','monster','month','moon','moral',
        'more','morning','mosquito','mother','motion','motor',
        'mountain','mouse','move','movie','much','muffin','mule',
        'multiply','muscle','museum','mushroom','music','must',
        'mutual','myself','mystery','myth','naive','name','napkin',
        'narrow','nasty','nation','nature','near','neck','need',
        'negative','neglect','neither','nephew','nerve','nest','net',
        'network','neutral','never','news','next','nice','night',
        'noble','noise','nominee','noodle','normal','north','nose',
        'notable','note','nothing','notice','novel','now','nuclear',
        'number','nurse','nut','oak','obey','object','oblige',
        'obscure','observe','obtain','obvious','occur','ocean',
        'october','odor','off','offer','office','often','oil','okay',
        'old','olive','olympic','omit','once','one','onion','online',
        'only','open','opera','opinion','oppose','option','orange',
        'orbit','orchard','order','ordinary','organ','orient',
        'original','orphan','ostrich','other','outdoor','outer',
        'output','outside','oval','oven','over','own','owner',
        'oxygen','oyster','ozone','pact','paddle','page','pair',
        'palace','palm','panda','panel','panic','panther','paper',
        'parade','parent','park','parrot','party','pass','patch',
        'path','patient','patrol','pattern','pause','pave','payment',
        'peace','peanut','pear','peasant','pelican','pen','penalty',
        'pencil','people','pepper','perfect','permit','person','pet',
        'phone','photo','phrase','physical','piano','picnic',
        'picture','piece','pig','pigeon','pill','pilot','pink',
        'pioneer','pipe','pistol','pitch','pizza','place','planet',
        'plastic','plate','play','please','pledge','pluck','plug',
        'plunge','poem','poet','point','polar','pole','police','pond',
        'pony','pool','popular','portion','position','possible',
        'post','potato','pottery','poverty','powder','power',
        'practice','praise','predict','prefer','prepare','present',
        'pretty','prevent','price','pride','primary','print',
        'priority','prison','private','prize','problem','process',
        'produce','profit','program','project','promote','proof',
        'property','prosper','protect','proud','provide','public',
        'pudding','pull','pulp','pulse','pumpkin','punch','pupil',
        'puppy','purchase','purity','purpose','purse','push','put',
        'puzzle','pyramid','quality','quantum','quarter','question',
        'quick','quit','quiz','quote','rabbit','raccoon','race',
        'rack','radar','radio','rail','rain','raise','rally','ramp',
        'ranch','random','range','rapid','rare','rate','rather',
        'raven','raw','razor','ready','real','reason','rebel',
        'rebuild','recall','receive','recipe','record','recycle',
        'reduce','reflect','reform','refuse','region','regret',
        'regular','reject','relax','release','relief','rely','remain',
        'remember','remind','remove','render','renew','rent','reopen',
        'repair','repeat','replace','report','require','rescue',
        'resemble','resist','resource','response','result','retire',
        'retreat','return','reunion','reveal','review','reward',
        'rhythm','rib','ribbon','rice','rich','ride','ridge','rifle',
        'right','rigid','ring','riot','ripple','risk','ritual',
        'rival','river','road','roast','robot','robust','rocket',
        'romance','roof','rookie','room','rose','rotate','rough',
        'round','route','royal','rubber','rude','rug','rule','run',
        'runway','rural','sad','saddle','sadness','safe','sail',
        'salad','salmon','salon','salt','salute','same','sample',
        'sand','satisfy','satoshi','sauce','sausage','save','say',
        'scale','scan','scare','scatter','scene','scheme','school',
        'science','scissors','scorpion','scout','scrap','screen',
        'script','scrub','sea','search','season','seat','second',
        'secret','section','security','seed','seek','segment',
        'select','sell','seminar','senior','sense','sentence',
        'series','service','session','settle','setup','seven',
        'shadow','shaft','shallow','share','shed','shell','sheriff',
        'shield','shift','shine','ship','shiver','shock','shoe',
        'shoot','shop','short','shoulder','shove','shrimp','shrug',
        'shuffle','shy','sibling','sick','side','siege','sight',
        'sign','silent','silk','silly','silver','similar','simple',
        'since','sing','siren','sister','situate','six','size',
        'skate','sketch','ski','skill','skin','skirt','skull','slab',
        'slam','sleep','slender','slice','slide','slight','slim',
        'slogan','slot','slow','slush','small','smart','smile',
        'smoke','smooth','snack','snake','snap','sniff','snow','soap',
        'soccer','social','sock','soda','soft','solar','soldier',
        'solid','solution','solve','someone','song','soon','sorry',
        'sort','soul','sound','soup','source','south','space','spare',
        'spatial','spawn','speak','special','speed','spell','spend',
        'sphere','spice','spider','spike','spin','spirit','split',
        'spoil','sponsor','spoon','sport','spot','spray','spread',
        'spring','spy','square','squeeze','squirrel','stable',
        'stadium','staff','stage','stairs','stamp','stand','start',
        'state','stay','steak','steel','stem','step','stereo','stick',
        'still','sting','stock','stomach','stone','stool','story',
        'stove','strategy','street','strike','strong','struggle',
        'student','stuff','stumble','style','subject','submit',
        'subway','success','such','sudden','suffer','sugar','suggest',
        'suit','summer','sun','sunny','sunset','super','supply',
        'supreme','sure','surface','surge','surprise','surround',
        'survey','suspect','sustain','swallow','swamp','swap','swarm',
        'swear','sweet','swift','swim','swing','switch','sword',
        'symbol','symptom','syrup','system','table','tackle','tag',
        'tail','talent','talk','tank','tape','target','task','taste',
        'tattoo','taxi','teach','team','tell','ten','tenant','tennis',
        'tent','term','test','text','thank','that','theme','then',
        'theory','there','they','thing','this','thought','three',
        'thrive','throw','thumb','thunder','ticket','tide','tiger',
        'tilt','timber','time','tiny','tip','tired','tissue','title',
        'toast','tobacco','today','toddler','toe','together','toilet',
        'token','tomato','tomorrow','tone','tongue','tonight','tool',
        'tooth','top','topic','topple','torch','tornado','tortoise',
        'toss','total','tourist','toward','tower','town','toy',
        'track','trade','traffic','tragic','train','transfer','trap',
        'trash','travel','tray','treat','tree','trend','trial',
        'tribe','trick','trigger','trim','trip','trophy','trouble',
        'truck','true','truly','trumpet','trust','truth','try','tube',
        'tuition','tumble','tuna','tunnel','turkey','turn','turtle',
        'twelve','twenty','twice','twin','twist','two','type',
        'typical','ugly','umbrella','unable','unaware','uncle',
        'uncover','under','undo','unfair','unfold','unhappy',
        'uniform','unique','unit','universe','unknown','unlock',
        'until','unusual','unveil','update','upgrade','uphold','upon',
        'upper','upset','urban','urge','usage','use','used','useful',
        'useless','usual','utility','vacant','vacuum','vague','valid',
        'valley','valve','van','vanish','vapor','various','vast',
        'vault','vehicle','velvet','vendor','venture','venue','verb',
        'verify','version','very','vessel','veteran','viable',
        'vibrant','vicious','victory','video','view','village',
        'vintage','violin','virtual','virus','visa','visit','visual',
        'vital','vivid','vocal','voice','void','volcano','volume',
        'vote','voyage','wage','wagon','wait','walk','wall','walnut',
        'want','warfare','warm','warrior','wash','wasp','waste',
        'water','wave','way','wealth','weapon','wear','weasel',
        'weather','web','wedding','weekend','weird','welcome','west',
        'wet','whale','what','wheat','wheel','when','where','whip',
        'whisper','wide','width','wife','wild','will','win','window',
        'wine','wing','wink','winner','winter','wire','wisdom','wise',
        'wish','witness','wolf','woman','wonder','wood','wool','word',
        'work','world','worry','worth','wrap','wreck','wrestle',
        'wrist','write','wrong','yard','year','yellow','you','young',
        'youth','zebra','zero','zone','zoo']

    def __init__(self,unknowninput="",password=""):
        super(Bip39EngClass,self).__init__()
        self.unknowninput = unknowninput
        self.password = password
        if self.unknowninput != "":
            try:
                self.setWordlist(self.unknowninput)
            except Exception as e:
                try:
                    self.setHex(self.unknowninput)
                except Exception as f:
                    self.wordlist = str("")
                    self.hex = str("")
                    raise TypeError("Initialization first input must be blank, hex, or a valid bip39 word list of lowercase words separated by a single space.  Wordlist decode attempt exception was: " + str(e) + ", and hex decode attempt exception thrown was: " + str(f))
                else:
                    self.hex = self.unknowninput
                    self.wordlist = Bip39EngClass.hex_to_wordlist(self.hex)
            else:
                self.wordlist = str("")
                for word in self.unknowninput:
                    self.wordlist = self.wordlist + word + " "
                self.wordlist = str(self.wordlist).lower().rstrip(" ")
                self.hex = Bip39EngClass.wordlist_to_hex(self.wordlist)
        else:
            self.wordlist = str("")
            self.hex = str("")
        self.unknowninput = None
        if self.password != "":
            self.password = str(self.password)
            if int(sys.version_info.major) == 2:
                self.password = unicode(self.password)
            self.password = unicodedata.normalize('NFC',self.password)
            self.password = str(self.password)
        else:
            self.password = str("")
        if self.wordlist != "":
            self.pbkdf2(self.wordlist,self.password)
        else:
            self.bip32seed = str("")
        if self.wordlist and "  " in self.wordlist:
            self.wordlist = str(self.wordlist).replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")

    def __str__(self):
        return self.wordlist

    def setPBKDF2password(self,password):
        self.password = str(password)
        if int(sys.version_info.major) == 2:
            self.password = unicode(self.password)
        self.password = unicodedata.normalize('NFC',self.password)
        self.password = str(self.password)
        if self.wordlist != "":
            self.pbkdf2(self.wordlist,self.password)

    def setWordlist(self,wordlist):
        self.wordlist = str(wordlist)
        if int(sys.version_info.major) == 2:
            self.wordlist = unicode(self.wordlist)
        self.wordlist = unicodedata.normalize('NFC',self.wordlist)
        self.wordlist = str(self.wordlist).lower()
        if self.wordlist and "  " in self.wordlist:
            self.wordlist = str(self.wordlist).replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        try:
            self.wordlistarray = self.wordlist.split()
        except:
            raise TypeError("Please make sure the input is a str of words, each separated by a single space, with no punctuation.")
        for word in self.wordlistarray:
            if word not in Bip39EngClass.BIP0039_ENG_WORDLIST:
                raise TypeError("Word: '" + str(word) + "' is not in the BIP38 English wordlist. Check spelling maybe.")
        self.wordlist = str("")
        for word in self.wordlistarray:
            self.wordlist = self.wordlist + str(" ") + str(word)
        self.wordlist = self.wordlist.rstrip(" ")
        if len(self.wordlistarray) > 93:
            self.wordlist = str("")
            self.hex = str("")
            raise TypeError("Worldlist size too large.  Greater than 992 bits of entropy not supported.")
        if len(self.wordlistarray) < 3:
            self.wordlist = str("")
            self.hex = str("")
            raise TypeError("Worldlist size too small.  Less than 32 bits of entropy not supported.")
        if len(self.wordlistarray) % 3:
            self.wordlist = str("")
            self.hex = str("")
            raise TypeError("Worldlist has too many/few words.  Must be in 3-word multiples.")
        self.wordlistarray = None
        try:
            self.hex = Bip39EngClass.wordlist_to_hex(self.wordlist)
        except Exception as e:
            self.wordlist = str("")
            self.hex = str("")
            raise Exception(str(e))
        else:
            self.pbkdf2(self.wordlist,self.password)

    def setHex(self,hexinput):
        self.hex = str(hexinput)
        if int(sys.version_info.major) == 2:
            self.hex = unicode(self.hex)
        self.hex = unicodedata.normalize('NFC',self.hex)
        self.hex = str(self.hex).replace("L","").replace("0x","")
        for char in self.hex:
            if char not in '0123456789abcdefABCDEF':
                self.hex = str("")
                raise TypeError("Input contains non-hex chars.")
                break
        if len(self.hex) % 2:
            self.hex = str("")
            raise Exception("Hex input is odd-length. Although many functions in this module auto-correct that, because of the high importance of not altering your Bip39 information, this error is thrown instead.  Please make sure the input hex is even number of hex chars, and in 8-char (4 byte) multiples, because Bip39 is specified for increments of 4 bytes.")
        try:
            self.test1 = binascii.unhexlify(self.hex)
            self.test2 = int(self.hex,16)
            self.test1, self.test2 = None, None
        except:
            self.hex = str("")
            raise TypeError("Input does not appear to be hex.")
        if len(self.hex) % 8:
            self.hex = str("")
            raise Exception("Input hex is not in 4-byte multiples (aka len(hexstr) % 8 != 0).  Bip39 works only in 4-byte multiples.")
        if len(self.hex) < 8:
            self.hex = str("")
            raise TypeError("Hex length too small.  Less than 32 bits of entropy not supported.")
        if len(self.hex) > 248:
            self.hex = str("")
            raise TypeError("Hex length too large.  Greater than 992 bits of entropy not supported.")
        try:
            self.wordlist = Bip39EngClass.hex_to_wordlist(self.hex)
            if self.wordlist and "  " in self.wordlist:
                self.wordlist = str(self.wordlist).replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        except Exception as e:
            self.wordlist = str("")
            self.hex = str("")
            raise Exception(str(e))
        else:
            self.pbkdf2(self.wordlist,self.password)

    def pbkdf2(self,words,password=""):
        from pbkdf2 import PBKDF2 as kdf_
        self.words = str(words)
        self.password = str(password)
        self.presalt = 'mnemonic'
        if int(sys.version_info.major) == 2:
            self.words = unicode(self.words)
            self.password = unicode(self.password)
            self.presalt = unicode(self.presalt)
        self.words = unicodedata.normalize('NFC',self.words)
        if "  " in self.words:
            self.words = str(self.words).replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        self.password = unicodedata.normalize('NFC',self.password)
        self.presalt = unicodedata.normalize('NFC',self.presalt)
        self.salt = str(self.presalt) + str(self.password)
        self.output = kdf_(self.words,self.salt,2048,macmodule=hmac,digestmodule=hashlib.sha512).read(64)
        self.bip32seed = hexlify_(self.output)
        assert len(self.bip32seed) == 128
        self.output, self.salt, self.presalt, self.words = None, None, None, None

    @staticmethod
    def wordlist_to_hex(wordlist):
        wordlist = str(wordlist)
        if int(sys.version_info.major) == 2:
            wordlist = unicode(wordlist)
        wordlist = unicodedata.normalize('NFC',wordlist)
        wordlist = str(wordlist).lower()
        if "  " in wordlist:
            wordlist = wordlist.replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        try:
            wordlistarray = str(wordlist).split(" ")
            if wordlistarray[0] == "":
                wordlistarray.pop(0)
        except:
            raise TypeError("Please make sure the input is a str of words, each separated by a single space, with no punctuation.")
        if len(wordlistarray) > 93:
            raise TypeError("Worldlist size too large.  Greater than 992 bits of entropy not supported.")
        if len(wordlistarray) < 3:
            raise TypeError("Worldlist size too small.  Less than 32 bits of entropy not supported.")
        if len(wordlistarray) % 3:
            raise TypeError("Worldlist has too many/few words.  Must be in 3-word multiples.  Wordlist is: " + str(wordlist) + ", and its list length appears to be " + str(len(wordlistarray)))
        for word in wordlistarray:
            if word not in Bip39EngClass.BIP0039_ENG_WORDLIST:
                raise TypeError("Word: '" + str(word) + "' is not in the BIP38 English wordlist. Check spelling maybe.")
        wordListIndexNumArray = []
        for i in range(len(wordlistarray)):
            wordListIndexNumArray.extend(' ')
            testWord = wordlistarray[i].replace(' ','')
            indexNum = Bip39EngClass.BIP0039_ENG_WORDLIST.index(testWord)
            wordListIndexNumArray[i] = indexNum
        wordListBinaryStr = str("")
        for i in range(len(wordListIndexNumArray)):
            newBinary = str(bin(int(wordListIndexNumArray[i])))
            if newBinary[:2] != "0b":
                raise Exception("Error converting wordlist into binary.")
            else:
                newBinary = newBinary[2:]
            for char in newBinary:
                if char not in '01':
                    raise Exception("Error (2) converting wordlist into binary.")
            if len(newBinary) < 11:
                for i in range(11 - len(newBinary)):
                    newBinary = "0" + newBinary
            if len(newBinary) > 11:
                raise Exception("Error (3) converting wordlist into binary.")
            assert len(newBinary) == 11
            wordListBinaryStr = wordListBinaryStr + str(newBinary)
        numberChecksumDigits = len(wordListBinaryStr) % 32
        binaryChecksum = wordListBinaryStr[(len(wordListBinaryStr) - numberChecksumDigits):]
        binaryNoCheck = wordListBinaryStr[:(-1*numberChecksumDigits)]
        hexoutput = hexlify_(int(binaryNoCheck,2))
        if len(hexoutput) % 8:
            for i in range(8 - (len(hexoutput) % 8)):
                hexoutput = "0" + hexoutput
        if len(hexoutput) < ((len(wordlistarray) // 3) * 8):
            for i in range(((len(wordlistarray) // 3) * 8) - len(hexoutput)):
                hexoutput = "0" + hexoutput
        assert not (len(hexoutput) % 2)
        checksum = sha256(hexoutput)
        checksumbinary = str(bin(int(checksum,16)))
        if checksumbinary[:2] != "0b":
            raise Exception("Error converting checksum into binary.")
        else:
            checksumbinary = checksumbinary[2:]
        for char in checksumbinary:
            if char not in '01':
                raise Exception("Error (2) converting checksum into binary.")
        if len(checksumbinary) < 256:
            for i in range(256 - len(checksumbinary)):
                checksumbinary = "0" + checksumbinary
        if len(checksumbinary) > 256:
            raise Exception("Error (3) converting checksum into binary.")
        assert len(checksumbinary) == 256 and 'b' not in checksumbinary
        if checksumbinary[:numberChecksumDigits] != binaryChecksum:
            raise Exception("Wordlist checksum didn't match.  Derived check: " + str(checksumbinary[:numberChecksumDigits]) + ", input check: " + str(binaryChecksum) + ", derived hex = " + str(hexoutput))
        else:
            return str(hexoutput)

    @staticmethod
    def hex_to_wordlist(hexinput):
        hexinput = str(hexinput)
        if int(sys.version_info.major) == 2:
            hexinput = unicode(hexinput)
        hexinput = unicodedata.normalize('NFC',hexinput)
        hexinput = str(hexinput).replace("L","").replace("0x","")
        for char in hexinput:
            if char not in '0123456789abcdefABCDEF':
                raise TypeError("Input contains non-hex chars.")
        if len(hexinput) % 2:
            raise Exception("Hex input is odd-length. Although many functions in this module auto-correct that, because of the high importance of not altering your Bip39 information, this error is thrown instead.  Please make sure the input hex is even number of hex chars, and in 8-char (4 byte) multiples, because Bip39 is specified for increments of 4 bytes.")
        try:
            test1 = binascii.unhexlify(hexinput)
            test2 = int(hexinput,16)
            test1, test2 = None, None
        except:
            raise TypeError("Input does not appear to be hex.")
        if len(hexinput) % 8:
            raise Exception("Input hex is not in 4-byte multiples (aka len(hexstr) % 8 != 0).  Bip39 works only in 4-byte multiples.")
        if len(hexinput) < 8:
            raise TypeError("Hex length too small.  Less than 32 bits of entropy not supported.")
        if len(hexinput) > 248:
            raise TypeError("Hex length too large.  Greater than 992 bits of entropy not supported.")
        checksumlength = int((len(hexinput) * 4) // 32)
        checksum = sha256(hexinput)
        hexbinary = str(bin(int(hexinput,16)))
        if hexbinary[:2] != "0b":
            raise Exception("Error converting hex input into binary.")
        else:
            hexbinary = hexbinary[2:]
        if len(hexbinary) % 2:
            hexbinary = "0" + hexbinary
        for char in hexbinary:
            if char not in '01':
                raise Exception("Error (2) converting hex input into binary.")
        if len(hexbinary) < (len(hexinput) * 4):
            for i in range((len(hexinput) * 4) - len(hexbinary)):
                hexbinary = "0" + hexbinary
        assert not (len(hexbinary) % 32)
        checksumbinary = str(bin(int(checksum,16)))
        if checksumbinary[:2] != "0b":
            raise Exception("Error converting checksum into binary.")
        else:
            checksumbinary = checksumbinary[2:]
        for char in checksumbinary:
            if char not in '01':
                raise Exception("Error (2) converting checksum into binary.")
        if len(checksumbinary) < 256:
            for i in range(256 - len(checksumbinary)):
                checksumbinary = "0" + checksumbinary
        if len(checksumbinary) > 256:
            raise Exception("Error (3) converting checksum into binary.")
        assert len(checksumbinary) == 256
        finalbinstr = str(hexbinary) + str(checksumbinary)[:checksumlength]
        assert not (len(finalbinstr) % 11)
        wordBinArray = [finalbinstr[i:i+11] for i in range(0,len(finalbinstr),11)]
        wordListStr = str("")
        for i in range(len(wordBinArray)):
            wordListStr = wordListStr + str(Bip39EngClass.BIP0039_ENG_WORDLIST[int(wordBinArray[i],2)]) + str(" ")
        wordListStr = str(wordListStr).rstrip(" ")
        if "  " in wordListStr:
            wordListStr = str(wordListStr).replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        return str(wordListStr)

class ElectrumWallet_V1(object):
    """
    >>> doctestwallet = ElectrumWallet_V1("f10bd6cb390f9ab686390433dcf66ec2")
    >>> doctestwallet.rootseed
    'f10bd6cb390f9ab686390433dcf66ec2'
    >>> doctestwallet.wordlist
    'forget gotten wise breath clear letter suppose jaw cast wheel midnight early'
    >>> doctestwallet.masterprivkey
    'bdef2e1b068cad476c3fa09ba5a936b0f0cfebf73a12b6abd20266c47af89899'
    >>> doctestwallet.masterpubkey
    '2321c4b46078b16702c4e05243f9e6b2fa93afffa35b988b28ef50fd5e6974cf0325b3df161e5aaffc7ba16398688e21d1ecbad3831ee954269db8fa775742af'
    >>> doctestwallet.get_privkey(0)
    '5e0e7a0c7ac46b1615d307ced23cb9a46e08125a40591dd11bcde29fe434b7fb'
    >>> doctestwallet.getpub(0)
    '040d47e6ce39d3fe6dd9eb1ca035bc1f88657652c37b38399093f4a156195ec676a76f860dd4e219da9d396f018da0de1fed8f00416f5012424f7411d2ca0dcca0'
    >>> ElectrumWallet_V1.get_pubkey("2321c4b46078b16702c4e05243f9e6b2fa93afffa35b988b28ef50fd5e6974cf0325b3df161e5aaffc7ba16398688e21d1ecbad3831ee954269db8fa775742af",0)
    '040d47e6ce39d3fe6dd9eb1ca035bc1f88657652c37b38399093f4a156195ec676a76f860dd4e219da9d396f018da0de1fed8f00416f5012424f7411d2ca0dcca0'
    >>> doctestwallet.get_privkey(0,True) # is change address
    'a0be1e12cd4baf242440d432702afcf145256152bdaaeb8d3b206204091ad5be'
    >>> ElectrumWallet_V1.get_pubkey("2321c4b46078b16702c4e05243f9e6b2fa93afffa35b988b28ef50fd5e6974cf0325b3df161e5aaffc7ba16398688e21d1ecbad3831ee954269db8fa775742af",0,True) # is change address
    '041db7c83ffa6489690b32fde54f2e1e7d88a9ffe8a180d22d16f5aeaed4ceb279e2462b47a62a76555778f968df2cf9aa39a299f9b93b6dc70c3013a4a4a00b4e'
    >>> doctestwallet2 = ElectrumWallet_V1("observe glare pocket left connect underneath further yours accept creak breast diamond")
    >>> doctestwallet2.rootseed
    'd3c1caa8325d861f0daa2989332b66ef'
    >>> doctestwallet2.wordlist
    'observe glare pocket left connect underneath further yours accept creak breast diamond'
    >>> doctestwallet2.masterprivkey
    'aff38177080ff7dce1b17bcf9cf6a0907301e3315640b6d13a7feabfdeca0b26'
    >>> doctestwallet2.masterpubkey
    'fdbd9042766aabb548f6982ce1f2f8c45892e3a07667a255aa4ab6499c82756613a43a88a979647157f39f8199a315c1d5c35c4c5f3bbc6d34b7b31ce0239208'
    >>> doctest3 = ElectrumWallet_V1("bbb4d6cb390f9ab686390433dcf66bbb")
    >>> doctest3.masterpubkey
    '41b1faff6281596e48f26f8cc1c28df16010bf5b85e937a3e606672b0911c6c4f363a0d08b09a7483ec132634eb9edd20fd1a20d50906040c704061661b95ef9'
    >>> doc4 = ElectrumWallet_V1("d0a240f3186f13bd502ebe5c3a416766")
    >>> doc4.wordlist
    'bang pale choose earth cool although loud voice favorite deserve after loud'
    >>> doc4.masterpubkey
    '5e8fd68a085de880f06f2a17b7f54fd70b60bafbbe1cd98422ddd5ae311b709f83110ecae740d4c4b3f6f32b9c43bfb5c4182418d3ac19e21929aa1bf99aaaf7'
    """

    ELECTRUM_ENG_V1_WORDLIST = [
         'like','just','love','know','never','want','time','out',
         'there','make','look','eye','down','only','think','heart',
         'back','then','into','about','more','away','still','them',
         'take','thing','even','through','long','always','world',
         'too','friend','tell','try','hand','thought','over','here',
         'other','need','smile','again','much','cry','been','night',
         'ever','little','said','end','some','those','around','mind',
         'people','girl','leave','dream','left','turn','myself',
         'give','nothing','really','off','before','something','find',
         'walk','wish','good','once','place','ask','stop','keep',
         'watch','seem','everything','wait','got','yet','made',
         'remember','start','alone','run','hope','maybe','believe',
         'body','hate','after','close','talk','stand','own','each',
         'hurt','help','home','god','soul','new','many','two',
         'inside','should','true','first','fear','mean','better',
         'play','another','gone','change','use','wonder','someone',
         'hair','cold','open','best','any','behind','happen','water',
         'dark','laugh','stay','forever','name','work','show','sky',
         'break','came','deep','door','put','black','together',
         'upon','happy','such','great','white','matter','fill',
         'past','please','burn','cause','enough','touch','moment',
         'soon','voice','scream','anything','stare','sound','red',
         'everyone','hide','kiss','truth','death','beautiful','mine',
         'blood','broken','very','pass','next','forget','tree',
         'wrong','air','mother','understand','lip','hit','wall',
         'memory','sleep','free','high','realize','school','might',
         'skin','sweet','perfect','blue','kill','breath','dance',
         'against','fly','between','grow','strong','under','listen',
         'bring','sometimes','speak','pull','person','become',
         'family','begin','ground','real','small','father','sure',
         'feet','rest','young','finally','land','across','today',
         'different','guy','line','fire','reason','reach','second',
         'slowly','write','eat','smell','mouth','step','learn',
         'three','floor','promise','breathe','darkness','push',
         'earth','guess','save','song','above','along','both',
         'color','house','almost','sorry','anymore','brother','okay',
         'dear','game','fade','already','apart','warm','beauty',
         'heard','notice','question','shine','began','piece','whole',
         'shadow','secret','street','within','finger','point',
         'morning','whisper','child','moon','green','story','glass',
         'kid','silence','since','soft','yourself','empty','shall',
         'angel','answer','baby','bright','dad','path','worry',
         'hour','drop','follow','power','war','half','flow','heaven',
         'act','chance','fact','least','tired','children','near',
         'quite','afraid','rise','sea','taste','window','cover',
         'nice','trust','lot','sad','cool','force','peace','return',
         'blind','easy','ready','roll','rose','drive','held','music',
         'beneath','hang','mom','paint','emotion','quiet','clear',
         'cloud','few','pretty','bird','outside','paper','picture',
         'front','rock','simple','anyone','meant','reality','road',
         'sense','waste','bit','leaf','thank','happiness','meet',
         'men','smoke','truly','decide','self','age','book','form',
         'alive','carry','escape','damn','instead','able','ice',
         'minute','throw','catch','leg','ring','course','goodbye',
         'lead','poem','sick','corner','desire','known','problem',
         'remind','shoulder','suppose','toward','wave','drink',
         'jump','woman','pretend','sister','week','human','joy',
         'crack','grey','pray','surprise','dry','knee','less',
         'search','bleed','caught','clean','embrace','future','king',
         'son','sorrow','chest','hug','remain','sat','worth','blow',
         'daddy','final','parent','tight','also','create','lonely',
         'safe','cross','dress','evil','silent','bone','fate',
         'perhaps','anger','class','scar','snow','tiny','tonight',
         'continue','control','dog','edge','mirror','month',
         'suddenly','comfort','given','loud','quickly','gaze','plan',
         'rush','stone','town','battle','ignore','spirit','stood',
         'stupid','yours','brown','build','dust','hey','kept','pay',
         'phone','twist','although','ball','beyond','hidden','nose',
         'taken','fail','float','pure','somehow','wash','wrap',
         'angry','cheek','creature','forgotten','heat','rip',
         'single','space','special','weak','whatever','yell',
         'anyway','blame','job','choose','country','curse','drift',
         'echo','figure','grew','laughter','neck','suffer','worse',
         'yeah','disappear','foot','forward','knife','mess',
         'somewhere','stomach','storm','beg','idea','lift','offer',
         'breeze','field','five','often','simply','stuck','win',
         'allow','confuse','enjoy','except','flower','seek',
         'strength','calm','grin','gun','heavy','hill','large',
         'ocean','shoe','sigh','straight','summer','tongue','accept',
         'crazy','everyday','exist','grass','mistake','sent','shut',
         'surround','table','ache','brain','destroy','heal','nature',
         'shout','sign','stain','choice','doubt','glance','glow',
         'mountain','queen','stranger','throat','tomorrow','city',
         'either','fish','flame','rather','shape','spin','spread',
         'ash','distance','finish','image','imagine','important',
         'nobody','shatter','warmth','became','feed','flesh','funny',
         'lust','shirt','trouble','yellow','attention','bare','bite',
         'money','protect','amaze','appear','born','choke',
         'completely','daughter','fresh','friendship','gentle',
         'probably','six','deserve','expect','grab','middle',
         'nightmare','river','thousand','weight','worst','wound',
         'barely','bottle','cream','regret','relationship','stick',
         'test','crush','endless','fault','itself','rule','spill',
         'art','circle','join','kick','mask','master','passion',
         'quick','raise','smooth','unless','wander','actually',
         'broke','chair','deal','favorite','gift','note','number',
         'sweat','box','chill','clothes','lady','mark','park','poor',
         'sadness','tie','animal','belong','brush','consume','dawn',
         'forest','innocent','pen','pride','stream','thick','clay',
         'complete','count','draw','faith','press','silver',
         'struggle','surface','taught','teach','wet','bless','chase',
         'climb','enter','letter','melt','metal','movie','stretch',
         'swing','vision','wife','beside','crash','forgot','guide',
         'haunt','joke','knock','plant','pour','prove','reveal',
         'steal','stuff','trip','wood','wrist','bother','bottom',
         'crawl','crowd','fix','forgive','frown','grace','loose',
         'lucky','party','release','surely','survive','teacher',
         'gently','grip','speed','suicide','travel','treat','vein',
         'written','cage','chain','conversation','date','enemy',
         'however','interest','million','page','pink','proud','sway',
         'themselves','winter','church','cruel','cup','demon',
         'experience','freedom','pair','pop','purpose','respect',
         'shoot','softly','state','strange','bar','birth','curl',
         'dirt','excuse','lord','lovely','monster','order','pack',
         'pants','pool','scene','seven','shame','slide','ugly',
         'among','blade','blonde','closet','creek','deny','drug',
         'eternity','gain','grade','handle','key','linger','pale',
         'prepare','swallow','swim','tremble','wheel','won','cast',
         'cigarette','claim','college','direction','dirty','gather',
         'ghost','hundred','loss','lung','orange','present','swear',
         'swirl','twice','wild','bitter','blanket','doctor',
         'everywhere','flash','grown','knowledge','numb','pressure',
         'radio','repeat','ruin','spend','unknown','buy','clock',
         'devil','early','false','fantasy','pound','precious',
         'refuse','sheet','teeth','welcome','add','ahead','block',
         'bury','caress','content','depth','despite','distant',
         'marry','purple','threw','whenever','bomb','dull','easily',
         'grasp','hospital','innocence','normal','receive','reply',
         'rhyme','shade','someday','sword','toe','visit','asleep',
         'bought','center','consider','flat','hero','history','ink',
         'insane','muscle','mystery','pocket','reflection','shove',
         'silently','smart','soldier','spot','stress','train','type',
         'view','whether','bus','energy','explain','holy','hunger',
         'inch','magic','mix','noise','nowhere','prayer','presence',
         'shock','snap','spider','study','thunder','trail','admit',
         'agree','bag','bang','bound','butterfly','cute','exactly',
         'explode','familiar','fold','further','pierce','reflect',
         'scent','selfish','sharp','sink','spring','stumble',
         'universe','weep','women','wonderful','action','ancient',
         'attempt','avoid','birthday','branch','chocolate','core',
         'depress','drunk','especially','focus','fruit','honest',
         'match','palm','perfectly','pillow','pity','poison','roar',
         'shift','slightly','thump','truck','tune','twenty','unable',
         'wipe','wrote','coat','constant','dinner','drove','egg',
         'eternal','flight','flood','frame','freak','gasp','glad',
         'hollow','motion','peer','plastic','root','screen','season',
         'sting','strike','team','unlike','victim','volume','warn',
         'weird','attack','await','awake','built','charm','crave',
         'despair','fought','grant','grief','horse','limit',
         'message','ripple','sanity','scatter','serve','split',
         'string','trick','annoy','blur','boat','brave','clearly',
         'cling','connect','fist','forth','imagination','iron',
         'jock','judge','lesson','milk','misery','nail','naked',
         'ourselves','poet','possible','princess','sail','size',
         'snake','society','stroke','torture','toss','trace','wise',
         'bloom','bullet','cell','check','cost','darling','during',
         'footstep','fragile','hallway','hardly','horizon',
         'invisible','journey','midnight','mud','nod','pause',
         'relax','shiver','sudden','value','youth','abuse','admire',
         'blink','breast','bruise','constantly','couple','creep',
         'curve','difference','dumb','emptiness','gotta','honor',
         'plain','planet','recall','rub','ship','slam','soar',
         'somebody','tightly','weather','adore','approach','bond',
         'bread','burst','candle','coffee','cousin','crime','desert',
         'flutter','frozen','grand','heel','hello','language',
         'level','movement','pleasure','powerful','random','rhythm',
         'settle','silly','slap','sort','spoken','steel','threaten',
         'tumble','upset','aside','awkward','bee','blank','board',
         'button','card','carefully','complain','crap','deeply',
         'discover','drag','dread','effort','entire','fairy','giant',
         'gotten','greet','illusion','jeans','leap','liquid','march',
         'mend','nervous','nine','replace','rope','spine','stole',
         'terror','accident','apple','balance','boom','childhood',
         'collect','demand','depression','eventually','faint',
         'glare','goal','group','honey','kitchen','laid','limb',
         'machine','mere','mold','murder','nerve','painful','poetry',
         'prince','rabbit','shelter','shore','shower','soothe',
         'stair','steady','sunlight','tangle','tease','treasure',
         'uncle','begun','bliss','canvas','cheer','claw','clutch',
         'commit','crimson','crystal','delight','doll','existence',
         'express','fog','football','gay','goose','guard','hatred',
         'illuminate','mass','math','mourn','rich','rough','skip',
         'stir','student','style','support','thorn','tough','yard',
         'yearn','yesterday','advice','appreciate','autumn','bank',
         'beam','bowl','capture','carve','collapse','confusion',
         'creation','dove','feather','girlfriend','glory',
         'government','harsh','hop','inner','loser','moonlight',
         'neighbor','neither','peach','pig','praise','screw',
         'shield','shimmer','sneak','stab','subject','throughout',
         'thrown','tower','twirl','wow','army','arrive','bathroom',
         'bump','cease','cookie','couch','courage','dim','guilt',
         'howl','hum','husband','insult','led','lunch','mock',
         'mostly','natural','nearly','needle','nerd','peaceful',
         'perfection','pile','price','remove','roam','sanctuary',
         'serious','shiny','shook','sob','stolen','tap','vain',
         'void','warrior','wrinkle','affection','apologize',
         'blossom','bounce','bridge','cheap','crumble','decision',
         'descend','desperately','dig','dot','flip','frighten',
         'heartbeat','huge','lazy','lick','odd','opinion','process',
         'puzzle','quietly','retreat','score','sentence','separate',
         'situation','skill','soak','square','stray','taint','task',
         'tide','underneath','veil','whistle','anywhere','bedroom',
         'bid','bloody','burden','careful','compare','concern',
         'curtain','decay','defeat','describe','double','dreamer',
         'driver','dwell','evening','flare','flicker','grandma',
         'guitar','harm','horrible','hungry','indeed','lace',
         'melody','monkey','nation','object','obviously','rainbow',
         'salt','scratch','shown','shy','stage','stun','third',
         'tickle','useless','weakness','worship','worthless',
         'afternoon','beard','boyfriend','bubble','busy','certain',
         'chin','concrete','desk','diamond','doom','drawn','due',
         'felicity','freeze','frost','garden','glide','harmony',
         'hopefully','hunt','jealous','lightning','mama','mercy',
         'peel','physical','position','pulse','punch','quit','rant',
         'respond','salty','sane','satisfy','savior','sheep','slept',
         'social','sport','tuck','utter','valley','wolf','aim',
         'alas','alter','arrow','awaken','beaten','belief','brand',
         'ceiling','cheese','clue','confidence','connection','daily',
         'disguise','eager','erase','essence','everytime',
         'expression','fan','flag','flirt','foul','fur','giggle',
         'glorious','ignorance','law','lifeless','measure','mighty',
         'muse','north','opposite','paradise','patience','patient',
         'pencil','petal','plate','ponder','possibly','practice',
         'slice','spell','stock','strife','strip','suffocate','suit',
         'tender','tool','trade','velvet','verse','waist','witch',
         'aunt','bench','bold','cap','certainly','click','companion',
         'creator','dart','delicate','determine','dish','dragon',
         'drama','drum','dude','everybody','feast','forehead',
         'former','fright','fully','gas','hook','hurl','invite',
         'juice','manage','moral','possess','raw','rebel','royal',
         'scale','scary','several','slight','stubborn','swell',
         'talent','tea','terrible','thread','torment','trickle',
         'usually','vast','violence','weave','acid','agony',
         'ashamed','awe','belly','blend','blush','character','cheat',
         'common','company','coward','creak','danger','deadly',
         'defense','define','depend','desperate','destination','dew',
         'duck','dusty','embarrass','engine','example','explore',
         'foe','freely','frustrate','generation','glove','guilty',
         'health','hurry','idiot','impossible','inhale','jaw',
         'kingdom','mention','mist','moan','mumble','mutter',
         'observe','ode','pathetic','pattern','pie','prefer','puff',
         'rape','rare','revenge','rude','scrape','spiral','squeeze',
         'strain','sunset','suspend','sympathy','thigh','throne',
         'total','unseen','weapon','weary']

    # NUMBER_OF_WORDS = len(ELECTRUM_ENG_V1_WORDLIST)
    NUMBER_OF_WORDS = 1626

    def __init__(self,unknowninput):
        super(ElectrumWallet_V1,self).__init__()
        self.unknowninput = unknowninput
        try:
            self.rootseed = ElectrumWallet_V1.wordlist_to_hex(self.unknowninput)
        except Exception as e:
            try:
                self.wordlist = ElectrumWallet_V1.hex_to_wordlist(self.unknowninput)
            except Exception as f:
                raise Exception("Input must be hex (exactly 32 hex chars) or 12 lowercase words with exactly one space between them.  Attempt to treat input as wordlist threw exception: '" + str(e) + "', and attempt to treat input as hex threw exception: '" + str(f) + "'.")
            else:
                self.rootseed = str(self.unknowninput)
        else:
            self.wordlist = str(self.unknowninput)
        self.unknowninput = None
        # Electrum key stretch does a hexlify on the hex, so the resulting hex chars are always in '0123456789'
        # Therefore I can do the quick and dirty replace("b'","") on Python 3's binary b'str' indicator without fear
        self.unchanged = str(str(binascii.hexlify(self.rootseed.encode('utf-8'))).replace("b'","").replace("'",""))
        self.masterprivkey = str(str(binascii.hexlify(self.rootseed.encode('utf-8'))).replace("b'","").replace("'",""))
        for i in range(100000):
            self.masterprivkey = hashlib.sha256(binascii.unhexlify(str(self.masterprivkey) + str(self.unchanged))).hexdigest()
        self.masterprivkey = hexlify_(self.masterprivkey)
        self.unchanged = None
        self.masterpubkey = str(privkey_to_pubkey(self.masterprivkey,False)[2:])

    def __str__(self):
        return self.wordlist

    def get_privkey(self,index,isChange=False):
        try:
            index = int(index)
        except:
            raise TypeError("Input must be an integer index number")
        if isChange:
            indexStr = str(str(index) + ":" + str("1") + ":")
        else:
            indexStr = str(str(index) + ":" + str("0") + ":")
        try:
            indexBytes = bytes(indexStr)
        except:
            indexBytes = bytes(indexStr,'utf-8')
        offset = double_sha256(hexlify_(indexBytes) + self.masterpubkey)
        return add_privkeys(offset,self.masterprivkey)

    def getpub(self,index,isChange=False):
        return ElectrumWallet_V1.get_pubkey(self.masterpubkey,index,isChange)

    @staticmethod
    def get_pubkey(masterpubkey,index,isChange=False):
        try:
            test1 = binascii.unhexlify(masterpubkey)
            test2 = int(masterpubkey,16)
            test1, test1 = None, None
        except:
            raise TypeError("First input must be a hex master public key")
        if len(masterpubkey) == 130:
            masterpubkey = masterpubkey[2:]
        elif len(masterpubkey) == 66:
            masterpubkey = str(uncompress_pubkey(masterpubkey))[2:]
        assert len(masterpubkey) == 128
        try:
            index = int(index)
        except:
            raise TypeError("Second input must be an integer index number")
        if isChange:
            indexStr = str(str(index) + ":" + str("1") + ":")
        else:
            indexStr = str(str(index) + ":" + str("0") + ":")
        try:
            indexBytes = bytes(indexStr)
        except:
            indexBytes = bytes(indexStr,'utf-8')
        offset = privkey_to_pubkey(double_sha256(hexlify_(indexBytes) + masterpubkey))
        masterpubkey = str("04" + masterpubkey) 
        return add_pubkeys(offset,masterpubkey,False)

    @staticmethod
    def hex_to_wordlist(hexinput):
        """
        Convert hex input to Electrum version 1 nmemonic word list (12 words)

        >>> ElectrumWallet_V1.hex_to_wordlist("0000000000000000000000007794c0ac")
        'like like like like like like like like like blame young truck'
        >>> ElectrumWallet_V1.hex_to_wordlist("f10bd6cb390f9ab686390433dcf66ec2")
        'forget gotten wise breath clear letter suppose jaw cast wheel midnight early'
        """

        hexinput = str(hexinput)
        if int(sys.version_info.major) == 2:
            hexinput = unicode(hexinput)
        hexinput = unicodedata.normalize('NFC',hexinput)
        hexinput = str(hexinput).replace("L","").replace("0x","")
        for char in hexinput:
            if char not in '0123456789abcdefABCDEF':
                raise TypeError("Input contains non-hex chars.")
        if len(hexinput) % 2:
            raise Exception("Hex input is odd-length. Although many functions in this module auto-correct that, because of the high importance of not altering your Electrum seed, this error is thrown instead.  Please make sure the input hex is exactly 32 hex chars.")
        try:
            test1 = binascii.unhexlify(hexinput)
            test2 = int(hexinput,16)
            test1, test2 = None, None
        except:
            raise TypeError("Input does not appear to be hex.")
        assert len(hexinput) == 32
        output = []
        for i in range(int(len(hexinput) // 8)):
            word = hexinput[8*i:8*i+8]
            x = int(word,16)
            w1 = (x % ElectrumWallet_V1.NUMBER_OF_WORDS)
            w2 = ((x // ElectrumWallet_V1.NUMBER_OF_WORDS) + w1) % ElectrumWallet_V1.NUMBER_OF_WORDS
            w3 = ((x // ElectrumWallet_V1.NUMBER_OF_WORDS // ElectrumWallet_V1.NUMBER_OF_WORDS) + w2) % ElectrumWallet_V1.NUMBER_OF_WORDS
            output += [ ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST[w1], ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST[w2], ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST[w3] ]
        return str(str(output).replace(",","").replace("[ ","").replace(" ]","").replace("[","").replace("]","").replace("u'","").replace("'",""))

    @staticmethod
    def wordlist_to_hex(wlist):
        """
        Convert Electrum version 1 nmemonic wordlist to hex

        >>> ElectrumWallet_V1.wordlist_to_hex("forget gotten wise breath clear letter suppose jaw cast wheel midnight early")
        'f10bd6cb390f9ab686390433dcf66ec2'
        >>> ElectrumWallet_V1.wordlist_to_hex("like like like like like like like like like blame young truck")
        '0000000000000000000000007794c0ac'
        """

        wlist = str(wlist)
        if int(sys.version_info.major) == 2:
            wlist = unicode(wlist)
        wlist = unicodedata.normalize('NFC',wlist)
        wlist = str(wlist).lower()
        if "  " in wlist:
            wlist = wlist.replace("  ","zzzzzzzz").replace(" ","").replace("zzzzzzzz"," ")
        try:
            wordlistarray = str(wlist).split(" ")
            if wordlistarray[0] == "":
                wordlistarray.pop(0)
        except:
            raise TypeError("Please make sure the input is a str of words, each separated by a single space, with no punctuation.")
        if len(wordlistarray) != 12:
            raise TypeError("Electrum version 1 word lists are exactly 12 words long, your list has a length of " + str(len(wordlistarray)))
        for word in wordlistarray:
            if word not in ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST:
                raise TypeError("Word: '" + str(word) + "' is not in the Electrum V1 wordlist. Check spelling maybe.")
        wlist = str(wlist).replace("\n","").replace("\r","")
        wlist = wlist.split()
        output = ''
        for i in range(int(len(wlist) // 3)):
            word1, word2, word3 = wlist[3*i:3*i+3]
            w1 = ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST.index(word1)
            w2 = (ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST.index(word2)) % ElectrumWallet_V1.NUMBER_OF_WORDS
            w3 = (ElectrumWallet_V1.ELECTRUM_ENG_V1_WORDLIST.index(word3)) % ElectrumWallet_V1.NUMBER_OF_WORDS
            x = w1 + ElectrumWallet_V1.NUMBER_OF_WORDS*((w2-w1) % ElectrumWallet_V1.NUMBER_OF_WORDS) + ElectrumWallet_V1.NUMBER_OF_WORDS*ElectrumWallet_V1.NUMBER_OF_WORDS*((w3-w2) % ElectrumWallet_V1.NUMBER_OF_WORDS)
            output += '%08x'%x
        output = hexlify_(binascii.unhexlify(output))
        assert len(output) == 32
        return str(output)

class MerkleTree_DoubleSHA256(object):
    """
    Returns the (hex str) merkle root of a set of hashes in the same fashion as Bitcoin block merkle roots are calculated.
    Merkle root can be retrieved with self.merkleroot variable, or with __str__ call on object.

    (Obviously, hash order matters.)

    # 8 tx block:
    # Bitcoin block height 332597 with hash 0000000000000000167ec294e8adce655b522f8c01b58a8f105bf63553232a55:
    >>> block332597 = MerkleTree_DoubleSHA256()
    >>> block332597.addhash("e4c11e327fc6e15f592d81f3ad318dfdf78eadd48f6477984e5b96e64b0d18fb") # coinbase tx
    >>> block332597.addhash("8f65f3313e138f7981f3a42d6cd51bce4b030fb32a5c7146ccb0942e1fd321c1")
    >>> block332597.addhash("93eebe13353267f7d0e9b1dd7f78418bc92307df524c1bc8a5fa1353c315313d")
    >>> block332597.addhash("eaba828c193281ee9bc9e2044264b2d1edce6841f0ee64b6f49f74d9065e1ca8")
    >>> block332597.addhash("75feb9690200c6076abe54cae5baf510dbd6073362cfd7a7d1f49e6cd8281072")
    >>> block332597.addhash("c54e1b45c054842c0b041e10a4b4a706192ae220d98a9f405e247db0124f5a24")
    >>> block332597.addhash("5f8398f24dd71f1dacd4405e5eaa3d0aa8b55a5568b8bcaac567fa298dbbd96b")
    >>> block332597.addhash("67b78609e1e43674865574fb897797818df47f2527bf7448466c6c203106ef2e")
    >>> block332597.merkleroot
    '9f668f40d374e088d91b2d6d49268d5ec339b6c037927376bf576699d6d9bebc'

    # 9 tx block:
    # Bitcoin block height 332058 with hash 00000000000000000afe58552525a71eb1b8e68e87fed1c888587f2a4bdab75e:
    >>> block332058 = MerkleTree_DoubleSHA256()
    >>> block332058.addhash("6b1546dcc0845ac48840897ec8c43ac75baf59e5071736e6f59793fdb990197a") # coinbase tx
    >>> block332058.addhash("253a24f5473766dec7b7f664ee244773cc8754a2466e5c3023fff9d0a84ca28a")
    >>> block332058.addhash("0684af00fd79e47c3ac6c14177343f744a0240c324c6285bf72b5511ce6a6db1")
    >>> block332058.addhash("bc57c28718f76cedaad5cea380381f1404c725a1e0d7e4e5cefa63855f525853")
    >>> block332058.addhash("c945995faa38e195ccaac2a446d912623d1e39835b9353b8df7c3d61456efe63")
    >>> block332058.addhash("8f30ca78e5b8b5f719be7c35326b20c3951f8e9ec52d0f50d98371e48ef5684e")
    >>> block332058.addhash("28df3b78aecae1457358858e9df2572155ca6e2027766ad88bf0aedcad9c7016")
    >>> block332058.addhash("ab3525e6c54efe8c8f585949ad56ffb19db8f276931619f8140522407169f9e7")
    >>> block332058.addhash("ba563dd24565b4b823e2831630395ab8c0d7e9cee7c94c703a7885ec4fdbc6f6")
    >>> str(block332058)
    'c21ab973b55e8add9f5cd2626afa4b15d4211d37b08aa619cbfe3fb6a5a87c84'

    # 1 tx block:
    # Bitcoin block height 332553 with hash 0000000000000000015407563eaafba9c752bc953f9c7178c2204e2010160727:
    >>> block332553 = MerkleTree_DoubleSHA256()
    >>> block332553.addhash("465162b508fae23245c6575740d022b0a51519d8553496a9d15fa3cc309c90a2") # coinbase tx
    >>> str(block332553)
    '465162b508fae23245c6575740d022b0a51519d8553496a9d15fa3cc309c90a2'
    """

    def __init__(self):
        super(MerkleTree_DoubleSHA256,self).__init__()
        self.hashlist = []
        self.merkleroot = str("")

    def addhash(self,hash):
        try:
            hash = hexlify_(binascii.unhexlify(hash))
            test2 = int(hash,16)
            test2 = None
            assert len(hash) == 64
        except:
            raise TypeError("Input must be 32 bytes (or 64 chars) of hex.")
        else:
            self.hashlist.append(str(hash))
            self.compute_merkleroot()

    def compute_merkleroot(self):
        if len(self.hashlist) == 0:
            self.merkleroot == str("") #  Not 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        elif len(self.hashlist) == 1:
            self.merkleroot = str(self.hashlist[0])
        elif len(self.hashlist) < 0:
            raise Exception("I don't think this is possible, but just on the off chance it is, I'll raise an exception for it.")
        elif len(self.hashlist) > 1:
            newlist3 = []
            for i in range(len(self.hashlist)): # Because Python uses pointers for lists
                newlist3.append(reverse_bytes(self.hashlist[i]))
            newtemporarylist = []
            for i in range(len(newlist3)): # Because Python uses pointers for lists
                newtemporarylist.append(newlist3[i])
            if len(newtemporarylist) % 2:
                tempval = newtemporarylist[-1]
                newtemporarylist.append(str(tempval))
            assert not len(newtemporarylist) % 2
            from math import log, ceil
            depthlevels = int(ceil(log(len(newtemporarylist),2)))
            for i in range(depthlevels):
                newdepthlist = []
                for j in range(int(len(newtemporarylist) // 2)):
                    k = 2*j
                    newdepthlist.append(double_sha256(str(str(newtemporarylist[k]) + str(newtemporarylist[k+1]))))
                for j in range(len(newtemporarylist)):
                    del newtemporarylist[-1]
                assert len(newtemporarylist) == 0
                for j in range(len(newdepthlist)):
                    newtemporarylist.append(newdepthlist[j])
                if len(newtemporarylist) % 2 and len(newtemporarylist) != 1:
                    tempvar = str(newtemporarylist[-1])
                    newtemporarylist.append(str(tempvar))
                if i != (depthlevels - 1):
                    assert not len(newtemporarylist) % 2
                for j in range(len(newdepthlist)):
                    del newdepthlist[-1]
                assert len(newdepthlist) == 0
                try:
                    del newdepthlist
                except:
                    pass
            assert len(newtemporarylist) == 1
            self.merkleroot = reverse_bytes(str(newtemporarylist[0]))
            del newtemporarylist[0]
            try:
                del newtemporarylist
            except:
                pass
        else:
            raise Exception("I don't think this is possible (2), but just on the off chance it is, I'll raise an exception for it.")
        return str(self.merkleroot)

    def __str__(self):
        return str(self.merkleroot)

class SimpleBitcoinTx(object):
    """
    Create from scratch, or import and break down into component parts, a SIMPLE bitcoin transaction.  Emphasis on SIMPLE.  Acceptable address types for inputs and outputs are normal bitcoin addresses and multisig P2SH addresses (but only multisig, not other P2SH scripts).  Additionally, a single OP_RETURN output can be added.  No other types of things can be done.  This method doesn't check provided signatures (although it makes valid new ones for created tx's).  It will probably fail in edge cases and some regular testing.  I wrote it just to prove to myself I understood basically how transactions worked.  DO NOT USE THIS FOR ANYTHING IMPORTANT.

    TODO:  Write doctests, check for bugs, fix bugs. Make sure doctests cover all use cases.
    """

    def __init__(self,input_tx="",importedredeemscripts=[],txversion=1):
        super(SimpleBitcoinTx,self).__init__()
        try:
            self.txversion = int(txversion)
        except:
            raise Exception("Bitcoin transaction version number must be int.")
        self.versionhex = hexlify_(self.txversion,8)
        self.versionhex = reverse_bytes(self.versionhex)
        assert len(self.versionhex) == 8
        self.inputs = []
        self.outputs = []
        self.sigs = []
        self.sigspubkeylist = []
        self.unsignedtx = str("")
        self.partialtx = str("")
        self.finaltx = str("")
        self.txid = str("INCOMPLETE")
        self.set_nlocktime(0)
        if input_tx != "":
            self.input_tx = str(input_tx)
            if len(self.input_tx) == 64:
                self.input_tx = download_tx_hex_from_id(self.input_tx)
            self.breakdown_tx(importedredeemscripts)

    def set_nlocktime(self,nlocktimeint):
        self.nlocktimeint = 0
        self.nlocktime = str("00000000")
        if len(self.inputs) != 0 and int(nlocktimeint) != 0:
            for i in range(len(self.inputs)):
                if self.inputs[i][2] == 4294967295 or self.inputs[i][2] == "ffffffff":
                    self.nlocktimeint = 0
                    self.nlocktime = str("00000000")
                    raise Exception("Cannot set nLockTime unless all inputs have sequence numbers less than 4294967295.")
        try:
            self.nlocktimeint = int(nlocktimeint)
        except:
            self.nlocktimeint = 0
            self.nlocktime = str("00000000")
            raise Exception("nLockTime value must be int.")
        if self.nlocktimeint < 0 or self.nlocktimeint > 4294967295:
            self.nlocktimeint = 0
            self.nlocktime = str("00000000")
            raise Exception("nLockTime input is out of range. Must be between 0 and 4294967295")
        self.nlocktime = hexlify_(self.nlocktimeint,8)
        self.nlocktimeint = int(self.nlocktime,16)
        self.nlocktime = reverse_bytes(self.nlocktime)
        try:
            assert len(self.nlocktime) == 8
        except:
            self.nlocktime = str("00000000")
            self.nlocktimeint = 0
            raise Exception("Unknown error setting nLockTime")
        self.serialize_to_unsigned_tx()

    @staticmethod
    def varint_bytesize(bytelength_int):
        if 'int' not in str(type(bytelength_int)) and 'long' not in str(type(bytelength_int)):
            raise Exception("Input size must be int.")
        try:
            size = int(bytelength_int)
        except:
            raise Exception("Input size must be int.")
        if size < 1:
            raise Exception("Input size must be a positive number, not zero or negative.")
        elif size > 18446744073709551615:
            raise Exception("This is a joke, right?")
        elif size < 253:
            hexsize = hexlify_(size,2)
            hexsize = str(hexsize)
            assert len(hexsize) == 2
        elif size < 65536:
            hexsize = hexlify_(size,4)
            assert len(hexsize) == 4
            hexsize = reverse_bytes(hexsize)
            hexsize = str(str("fd") + hexsize)
            assert len(hexsize) == 6
        elif size < 4294967296:
            hexsize = hexlify_(size,8)
            assert len(hexsize) == 8
            hexsize = reverse_bytes(hexsize)
            hexsize = str(str("fe") + hexsize)
            assert len(hexsize) == 10
        elif size < 18446744073709551616:
            hexsize = hexlify_(size,16)
            assert len(hexsize) == 16
            hexsize = reverse_bytes(hexsize)
            hexsize = str(str("ff") + hexsize)
            assert len(hexsize) == 18
        return hexsize

    def add_input(self,txID,txid_vout,asm_hex="",redeemscript="",sequencenumber=4294967295):
        try:
            sequencenumber = int(sequencenumber)
            assert 'int' in str(type(sequencenumber)) or 'long' in str(type(sequencenumber))
        except:
            raise Exception("Sequence number must be an integer.")
        if self.nlocktimeint != 0 and sequencenumber == 4294967295:
            raise Exception("Sequence number for input should be less than 4294967295 if nLockTime is not zero.")
        if sequencenumber < 0 or sequencenumber > 4294967295:
            raise Exception("Sequence number must be in the range 0 to 4294967295 (inclusive)")
        try:
            txID2 = txID
            txID = binascii.unhexlify(txID)
        except:
            raise Exception("Tx ID does not appear to be hex.")
        else:
            txID = hexlify_(txID)
        assert len(txID) == 64
        assert binascii.unhexlify(txID) == binascii.unhexlify(txID2)
        try:
            txid_vout = int(txid_vout)
        except:
            raise Exception("vout must be an integer.")
        if txid_vout < 0 or txid_vout > 18446744073709551615:
            raise Exception("vout must be in the range 0 to 18446744073709551615 (inclusive)")
        if asm_hex == "":
            asm_hex, xamount = SimpleBitcoinTx.get_asm_and_amount_satoshis_from_tx_hex(SimpleBitcoinTx.download_tx_hex_from_id(txID),txid_vout)
        try:
            asm = binascii.unhexlify(asm_hex)
        except:
            raise Exception("asm for input must not be blank and must be in hex form.")
        else:
            asm = hexlify_(asm)
            assert binascii.unhexlify(asm_hex) == binascii.unhexlify(asm)
        if asm[:6] != "76a914" and asm[:4] != "a914":
            raise Exception("This method can only handle normal Bitcoin addresses and multisig addresses as inputs. The class name is 'SimpleBitcoinTx' after all...")
        elif asm[:6] == "76a914" and len(asm) != 50:
            raise Exception("Error with asm.  Hexstr length should be 50 (25 bytes) but it's not.")
        elif asm[:4] == "a914" and len(asm) != 46:
            raise Exception("Error with asm.  Hexstr length should be 46 (23 bytes) but it's not.")
        elif asm[:6] == "76a914" and asm[46:] != "88ac":
            raise Exception("Error with asm.  Last two bytes do not represent OP_EQUALVERIFY OP_CHECKSIG.")
        elif asm[:4] == "a914" and asm[44:] != "87":
            raise Exception("Error with asm.  Last byte does not represent OP_EQUAL.")
        assert (len(asm) == 50 and asm[:6] == "76a914" and asm[46:] == "88ac") or (len(asm) == 46 and asm[:4] == "a914" and asm[44:] == "87")
        redeemscript = str(redeemscript)
        if redeemscript != "":
            try:
                test = binascii.unhexlify(redeemscript)
            except:
                raise Exception("Redeem script does not appear to be hex")
            else:
                redeemscript = hexlify_(test)
                assert binascii.unhexlify(redeemscript) == binascii.unhexlify(test)
                test = None
        self.inputs.append([txID,txid_vout,asm,redeemscript,sequencenumber])
        try:
            self.serialize_to_unsigned_tx()
        except:
            raise Exception("Error adding input.  Please make sure the input is only a normal bitcoin address or multisig P2SH address. The class name is 'SimpleBitcoinTx' for a reason!")
        if asm[:6] == "76a914" and len(asm) == 50:
            self.sigs.append(str(""))
            self.sigspubkeylist.append(str(""))
            assert len(self.sigs) == len(self.sigspubkeylist)
        elif asm[:4] == "a914" and len(asm) == 46:
            if redeemscript == "":
                del self.inputs[-1]
                self.serialize_to_unsigned_tx()
                raise Exception("Redeem script not provided for multisig input")
            try:
                m_num_keys, y = self.validate_redeem_script_and_return_keys(redeemscript)
            except Exception as e:
                del self.inputs[-1]
                self.serialize_to_unsigned_tx()
                raise Exception(str(e))
            else:
                y = None
            try:
                self.sigs.append([])
                self.sigspubkeylist.append([])
            except:
                del self.inputs[-1]
                self.serialize_to_unsigned_tx()
                raise Exception("Error attempting to append empty list to list.")
            try:
                assert len(self.sigs) == len(self.sigspubkeylist)
            except Exception as e:
                del self.inputs[-1]
                self.serialize_to_unsigned_tx()
                raise Exception(str(e))
            for i in range(m_num_keys):
                self.sigs[-1].append(str(""))
                self.sigspubkeylist[-1].append(str(""))
                try:
                    assert len(self.sigs) == len(self.sigspubkeylist)
                except Exception as e:
                    del self.inputs[-1]
                    self.serialize_to_unsigned_tx()
                    raise Exception(str(e))
        else:
            raise Exception("Only normal bitcoin addresses and multisig P2SH addresses can be added as inputs. The class name is 'SimpleBitcoinTx' for a reason!")

    def add_output(self,addressoropreturn,amountinBTCoropreturnhex):
        tempvar = str(addressoropreturn)
        tempvar2 = str(amountinBTCoropreturnhex)
        if tempvar == "OP_RETURN":
            for i in range(len(self.outputs)):
                if "OP_RETURN" in self.outputs[i][0]:
                    raise Exception("Cannot add output. Only one OP_RETURN output is allowed in a tx.")
            try:
                test3 = binascii.unhexlify(amountinBTCoropreturnhex)
            except:
                raise Exception("OP_RETURN data must be hex. Burning money or other data types not allowed. This class is called 'SimpleBitcoinTx' for a reason!")
            else:
                tempvar2 = hexlify_(test3)
                test3 = None
                tempvar = str("OP_RETURN")
                outputamount = tempvar2
        elif tempvar[:1] == "1":
            try:
                addresshex, isValid = base58_decode(tempvar,True,False)
            except:
                raise Exception("Error attempting to decode bitcoin address that is being added as an output.")
            if not isValid:
                raise Exception("Base58 checkum doesn't match for bitcoin address that is being added as an output.")
            if len(addresshex[2:]) != 40:
                raise Exception("Error decoding bitcoin address into hash160: Length is not 20 bytes.")
            if addresshex[:2] != "00":
                raise Exception("Hash160 does not begin with '00' even though base58 string begins with 1. This exception should never happen.")
            try:
                outputamount = float(tempvar2)
            except:
                raise Exception("Output amount (second input variable) must be a number (int or float or str(int)/str(float))")
        elif tempvar[:1] == "3":
            try:
                addresshex, isValid = base58_decode(tempvar,True,False)
            except:
                raise Exception("Error attempting to decode P2SH address that is being added as an output.")
            if not isValid:
                raise Exception("Base58 checkum doesn't match for P2SH address that is being added as an output.")
            if len(addresshex[2:]) != 40:
                raise Exception("Error decoding P2SH address into hash160: Length is not 20 bytes.")
            if addresshex[:2] != "05":
                raise Exception("Hash160 does not begin with '05' even though base58 string begins with 3. This exception should never happen.")
            try:
                outputamount = float(tempvar2)
            except:
                raise Exception("Output amount (second input variable) must be a number (int or float or str(int)/str(float))")
        else:
            raise Exception("Valid input variables to add for output are bitcoin addresses, multisig address, and 'OP_RETURN'. Nothing else. This class is called 'SimpleBitcoinTx' for a reason!")
        self.outputs.append([tempvar,outputamount])
        self.serialize_to_unsigned_tx()

    def serialize_to_unsigned_tx(self):
        if len(self.inputs) == 0 or len(self.outputs) == 0:
            self.unsignedtx = str("")
            return
        self.unsignedtx = str("")
        self.unsignedtx = str(self.versionhex) + str(SimpleBitcoinTx.varint_bytesize(len(self.inputs)))
        for i in range(len(self.inputs)):
            self.unsignedtx = self.unsignedtx + str(reverse_bytes(self.inputs[i][0]))
            assert len(str(reverse_bytes(hexlify_(int(self.inputs[i][1]),8)))) == 8
            self.unsignedtx = self.unsignedtx + str(reverse_bytes(hexlify_(int(self.inputs[i][1]),8)))
            self.unsignedtx = self.unsignedtx + str("00")
            assert len(str(reverse_bytes(hexlify_(int(self.inputs[i][4]),8)))) == 8
            self.unsignedtx = self.unsignedtx + str(reverse_bytes(hexlify_(int(self.inputs[i][4]),8)))
        self.unsignedtx = self.unsignedtx + str(SimpleBitcoinTx.varint_bytesize(len(self.outputs)))
        for i in range(len(self.outputs)):
            if self.outputs[i][0] == "OP_RETURN":
                lenopreturndata = str(SimpleBitcoinTx.varint_bytesize(int(len(self.outputs[i][1]) // 2)))
                outputstr = str("6a") + lenopreturndata + str(self.outputs[i][1]) # OP_RETURN + size of data + data
                totaloutputlen = str(SimpleBitcoinTx.varint_bytesize(int(len(outputstr) // 2)))
                self.unsignedtx = self.unsignedtx + str("0000000000000000") + totaloutputlen + outputstr
                                  # string of zeros is the amount of satoshis being sent.
                                  # This module doesn't allow money to be burned, so it's set to zero.
            else:
                amount = int((self.outputs[i][1]) * (10**8))
                amount = str(reverse_bytes(hexlify_(amount,16)))
                assert len(amount) == 16
                self.unsignedtx = self.unsignedtx + amount
                outputhex, isValid = base58_decode(self.outputs[i][0],True,False)
                if not isValid:
                    self.unsignedtx = str("")
                    raise Exception("Base58 decode checksum fail in output number " + str(i))
                try:
                    assert len(outputhex) == 42
                except:
                    self.unsignedtx = str("")
                    raise Exception("Hash160 length error. Only normal bitcoin addresses, multisig addresses, and OP_RETURN are acceptable for outputs. This class is called 'SimpleBitcoinTx' for a reason!")
                if outputhex[:2] == "05":
                    asm = str("a9") + str(SimpleBitcoinTx.varint_bytesize(int(len(outputhex[2:]) // 2))) + str(outputhex[2:]) + str("87") # OP_HASH160 .... OP_EQUAL
                elif outputhex[:2] == "00":
                    asm = str("76a9") + str(SimpleBitcoinTx.varint_bytesize(int(len(outputhex[2:]) // 2))) + str(outputhex[2:]) + str("88ac") # OP_DUP OP_HASH160 .... OP_EQUALVERIFY OP_CHECKSIG
                else:
                    self.unsignedtx = str("")
                    raise Exception("Output " + str(i) + " is not a recognized address. Only 1BitcoinAddress and 3PaytoScriptHash address formats are valid. This class is called 'SimpleBitcoinTx' for a reason!")
                asm = str(asm)
                asmlen = SimpleBitcoinTx.varint_bytesize(int(len(asm) // 2))
                self.unsignedtx = self.unsignedtx + str(asmlen) + asm
        self.unsignedtx = self.unsignedtx + self.nlocktime
        self.unsignedtx = str(self.unsignedtx)

    def add_multisig_amount_to_sigs_len(self,redeemscript):
        try:
            m_num_keys, y = self.validate_redeem_script_and_return_keys(redeemscript)
        except Exception as e:
            raise Exception(str(e))
        else:
            y = None
        try:
            self.sigs.append([])
            self.sigspubkeylist.append([])
        except:
            raise Exception("Error attempting to append empty list to list.")
        assert len(self.sigs) == len(self.sigspubkeylist)
        for i in range(m_num_keys):
            self.sigs[-1].append(str(""))
            self.sigspubkeylist[-1].append(str(""))
            assert len(self.sigs) == len(self.sigspubkeylist)

    def is_siglist_complete(self):
        assert len(self.sigs) == len(self.sigspubkeylist)
        iscomplete = True
        for i in range(len(self.sigs)):
            if 'list' not in str(type(self.sigs[i])):
                if self.sigs[i] == "":
                    iscomplete = False
                    break
            else:
                for j in range(len(self.sigs[i])):
                    if self.sigs[i][j] == "":
                        iscomplete = False
                        break
        return iscomplete

    def signtx(self,privkey):
        try:
            privkey = privkey_to_hexstr(privkey)
        except:
            raise Exception("Invalid private key entered.")
        for i in range(len(self.inputs)):
            current_asm = str(self.inputs[i][2])
            if current_asm[:4] == "76a9" and len(current_asm) == 50:
                asmC = hash160(privkey_to_pubkey(privkey,True))
                asmU = hash160(privkey_to_pubkey(privkey,False))
                if asmC == current_asm[6:-4] or asmU == current_asm[6:-4]:
                    if self.sigs[i] == "":
                        self.sign_specific_input_regularkey(privkey,i)
            elif current_asm[:4] == "a914" and len(current_asm) == 46:
                pubC = privkey_to_pubkey(privkey,True)
                pubU = privkey_to_pubkey(privkey,False)
                m_required, rs_pubkeys = SimpleBitcoinTx.validate_redeem_script_and_return_keys(self.inputs[i][3])
                sigscounter = 0
                for j in range(len(self.sigs[i])):
                    if self.sigs[i][j] != "":
                        sigscounter = sigscounter + 1
                for j in range(m_required - sigscounter):
                    if pubC in rs_pubkeys:
                        if pubC not in self.sigspubkeylist[i]:
                            self.sign_specific_input_multisig(privkey,i)
                    elif pubU in rs_pubkeys:
                        if pubU not in self.sigspubkeylist[i]:
                            self.sign_specific_input_multisig(privkey,i)
            else:
                raise Exception("Bad asm check on input " + str(i))
        # self.update_tx_with_sigs()
        # Methods called already call that at the end of them.

    def sign_specific_input_regularkey(self,privkey,tx_input_num):
        try:
            privkey = hexlify_(binascii.unhexlify(privkey))
            test = int(privkey,16); test = None
            assert len(privkey) == 64
        except:
            raise Exception("Private key input must be 32 bytes (or 64 chars) of hex.")
        try:
            tx_input_num = int(tx_input_num)
            assert tx_input_num < len(self.inputs)
        except:
            raise Exception("vout number is not int or is higher than total number of inputs.")
        if 'list' in str(type(self.sigs[tx_input_num])):
            raise Exception("Cannot sign P2SH input with this method.")
        if (not (self.inputs[tx_input_num][2])) or self.inputs[tx_input_num][2] == "":
            raise Exception("asm hex for input cannot be blank when this method is called.")
        if self.inputs[tx_input_num][2][:4] != "76a9":
            raise Exception("Unknown asm associated with input.")
        try:
            self.serialize_to_unsigned_tx()
        except:
            raise Exception("All inputs and outputs must be added before any signatures can be made on the tx.")
        # Reconstruct tx from scratch
        sighashall_thisinput_tx = str("")
        sighashall_thisinput_tx = str(self.versionhex) + str(SimpleBitcoinTx.varint_bytesize(len(self.inputs)))
        for i in range(len(self.inputs)):
            sighashall_thisinput_tx = sighashall_thisinput_tx + str(reverse_bytes(self.inputs[i][0]))
            assert len(str(reverse_bytes(hexlify_(int(self.inputs[i][1]),8)))) == 8
            sighashall_thisinput_tx = sighashall_thisinput_tx + str(reverse_bytes(hexlify_(int(self.inputs[i][1]),8)))
            if i != tx_input_num:
                sighashall_thisinput_tx = sighashall_thisinput_tx + str("00")
            else:
                asm_len = hexlify_(int(len(self.inputs[tx_input_num][2]) // 2),2) # I use hex strs, so the length is always divided by two
                assert len(asm_len) == 2
                assert asm_len == "19" # For now I'm just asserting it, although if other address lengths become common, it can be changed.
                sighashall_thisinput_tx = sighashall_thisinput_tx + str(asm_len) + str(self.inputs[tx_input_num][2])
            assert len(str(reverse_bytes(hexlify_(int(self.inputs[i][4]),8)))) == 8
            sighashall_thisinput_tx = sighashall_thisinput_tx + str(reverse_bytes(hexlify_(int(self.inputs[i][4]),8)))
        sighashall_thisinput_tx = sighashall_thisinput_tx + str(SimpleBitcoinTx.varint_bytesize(len(self.outputs)))
        for i in range(len(self.outputs)):
            if self.outputs[i][0] == "OP_RETURN":
                lenopreturndata = str(SimpleBitcoinTx.varint_bytesize(int(len(self.outputs[i][1]) // 2)))
                outputstr = str("6a") + lenopreturndata + str(self.outputs[i][1]) # OP_RETURN + size of data + data
                totaloutputlen = str(SimpleBitcoinTx.varint_bytesize(int(len(outputstr) // 2)))
                sighashall_thisinput_tx = sighashall_thisinput_tx + str("0000000000000000") + totaloutputlen + outputstr
                                  # string of zeros is the amount of satoshis being sent.
                                  # This module doesn't allow money to be burned, so it's set to zero.
            else:
                amount = int((self.outputs[i][1]) * (10**8))
                amount = str(reverse_bytes(hexlify_(amount,16)))
                assert len(amount) == 16
                sighashall_thisinput_tx = sighashall_thisinput_tx + amount
                outputhex, isValid = base58_decode(self.outputs[i][0],True,False)
                if not isValid:
                    sighashall_thisinput_tx = str("")
                    raise Exception("Base58 decode checksum fail in output number " + str(i))
                try:
                    assert len(outputhex) == 42
                except:
                    sighashall_thisinput_tx = str("")
                    raise Exception("Hash160 length error. Only normal bitcoin addresses, multisig addresses, and OP_RETURN are acceptable for outputs. This class is called 'SimpleBitcoinTx' for a reason!")
                if outputhex[:2] == "05":
                    asm = str("a9") + str(SimpleBitcoinTx.varint_bytesize(int(len(outputhex[2:]) // 2))) + str(outputhex[2:]) + str("87") # OP_HASH160 .... OP_EQUAL
                elif outputhex[:2] == "00":
                    asm = str("76a9") + str(SimpleBitcoinTx.varint_bytesize(int(len(outputhex[2:]) // 2))) + str(outputhex[2:]) + str("88ac") # OP_DUP OP_HASH160 .... OP_EQUALVERIFY OP_CHECKSIG
                else:
                    sighashall_thisinput_tx = str("")
                    raise Exception("Output " + str(i) + " is not a recognized address. Only 1BitcoinAddress and 3PaytoScriptHash address formats are valid. This class is called 'SimpleBitcoinTx' for a reason!")
                asm = str(asm)
                asmlen = SimpleBitcoinTx.varint_bytesize(int(len(asm) // 2))
                sighashall_thisinput_tx = sighashall_thisinput_tx + str(asmlen) + asm
        sighashall_thisinput_tx = sighashall_thisinput_tx + self.nlocktime # Add lock time
        sighashall_thisinput_tx = sighashall_thisinput_tx + str("01000000") # add SIGHASH_ALL to end
        sighashall_thisinput_tx = str(sighashall_thisinput_tx)
        txhash = double_sha256(sighashall_thisinput_tx)
        newsig, compressedpubkey = sign_hash(txhash,privkey,double_sha256(hexlify_(os.urandom(32),64)),True)
        uncompressedpubkey = uncompress_pubkey(compressedpubkey)
        newsig = str(newsig + str("01")) # add SIGHASH_ALL to end of sig
        if hash160(compressedpubkey) == self.inputs[tx_input_num][2][6:-4]:
            self.sigspubkeylist[tx_input_num] = str(compressedpubkey)
        elif hash160(uncompressedpubkey) == self.inputs[tx_input_num][2][6:-4]:
            self.sigspubkeylist[tx_input_num] = str(uncompressedpubkey)
        else:
            raise Exception("Public key assigned to sig does not appear to match input asm from input; Singing error highly likely.")
        self.sigs[tx_input_num] = str(newsig)
        self.update_tx_with_sigs()

    def sign_specific_input_multisig(self,privkey,tx_input_num):
        try:
            privkey = hexlify_(binascii.unhexlify(privkey))
            test = int(privkey,16); test = None
            assert len(privkey) == 64
        except:
            raise Exception("Private key input must be 32 bytes (or 64 chars) of hex.")
        try:
            tx_input_num = int(tx_input_num)
            assert tx_input_num < len(self.inputs)
        except:
            raise Exception("vout number is not int or is higher than total number of inputs.")
        if 'list' not in str(type(self.sigs[tx_input_num])):
            raise Exception("Cannot sign non-P2SH input with this method.")
        try:
            self.serialize_to_unsigned_tx()
        except:
            raise Exception("All inputs and outputs must be added before any signatures can be made on the tx.")
        # Reconstruct tx from scratch
        sighashall_thisinput_tx = str("")
        sighashall_thisinput_tx = str(self.versionhex) + str(SimpleBitcoinTx.varint_bytesize(len(self.inputs)))
        for i in range(len(self.inputs)):
            sighashall_thisinput_tx = sighashall_thisinput_tx + str(reverse_bytes(self.inputs[i][0]))
            assert len(str(reverse_bytes(hexlify_(int(self.inputs[i][1]),8)))) == 8
            sighashall_thisinput_tx = sighashall_thisinput_tx + str(reverse_bytes(hexlify_(int(self.inputs[i][1]),8)))
            if i != tx_input_num:
                sighashall_thisinput_tx = sighashall_thisinput_tx + str("00")
            else:
                redeemscript_len = str(SimpleBitcoinTx.varint_bytesize(int(len(self.inputs[tx_input_num][3]) // 2)))
                sighashall_thisinput_tx = sighashall_thisinput_tx + str(redeemscript_len) + str(self.inputs[tx_input_num][3])
            assert len(str(reverse_bytes(hexlify_(int(self.inputs[i][4]),8)))) == 8
            sighashall_thisinput_tx = sighashall_thisinput_tx + str(reverse_bytes(hexlify_(int(self.inputs[i][4]),8)))
        sighashall_thisinput_tx = sighashall_thisinput_tx + str(SimpleBitcoinTx.varint_bytesize(len(self.outputs)))
        for i in range(len(self.outputs)):
            if self.outputs[i][0] == "OP_RETURN":
                lenopreturndata = str(SimpleBitcoinTx.varint_bytesize(int(len(self.outputs[i][1]) // 2)))
                outputstr = str("6a") + lenopreturndata + str(self.outputs[i][1]) # OP_RETURN + size of data + data
                totaloutputlen = str(SimpleBitcoinTx.varint_bytesize(int(len(outputstr) // 2)))
                sighashall_thisinput_tx = sighashall_thisinput_tx + str("0000000000000000") + totaloutputlen + outputstr
                                  # string of zeros is the amount of satoshis being sent.
                                  # This module doesn't allow money to be burned, so it's set to zero.
            else:
                amount = int((self.outputs[i][1]) * (10**8))
                amount = str(reverse_bytes(hexlify_(amount,16)))
                assert len(amount) == 16
                sighashall_thisinput_tx = sighashall_thisinput_tx + amount
                outputhex, isValid = base58_decode(self.outputs[i][0],True,False)
                if not isValid:
                    sighashall_thisinput_tx = str("")
                    raise Exception("Base58 decode checksum fail in output number " + str(i))
                try:
                    assert len(outputhex) == 42
                except:
                    sighashall_thisinput_tx = str("")
                    raise Exception("Hash160 length error. Only normal bitcoin addresses, multisig addresses, and OP_RETURN are acceptable for outputs. This class is called 'SimpleBitcoinTx' for a reason!")
                if outputhex[:2] == "05":
                    asm = str("a9") + str(SimpleBitcoinTx.varint_bytesize(int(len(outputhex[2:]) // 2))) + str(outputhex[2:]) + str("87") # OP_HASH160 .... OP_EQUAL
                elif outputhex[:2] == "00":
                    asm = str("76a9") + str(SimpleBitcoinTx.varint_bytesize(int(len(outputhex[2:]) // 2))) + str(outputhex[2:]) + str("88ac") # OP_DUP OP_HASH160 .... OP_EQUALVERIFY OP_CHECKSIG
                else:
                    sighashall_thisinput_tx = str("")
                    raise Exception("Output " + str(i) + " is not a recognized address. Only 1BitcoinAddress and 3PaytoScriptHash address formats are valid. This class is called 'SimpleBitcoinTx' for a reason!")
                asm = str(asm)
                asmlen = SimpleBitcoinTx.varint_bytesize(int(len(asm) // 2))
                sighashall_thisinput_tx = sighashall_thisinput_tx + str(asmlen) + asm
        sighashall_thisinput_tx = sighashall_thisinput_tx + self.nlocktime # Add lock time
        sighashall_thisinput_tx = sighashall_thisinput_tx + str("01000000") # add SIGHASH_ALL to end
        sighashall_thisinput_tx = str(sighashall_thisinput_tx)
        txhash = double_sha256(sighashall_thisinput_tx)
        newsig, compressedpubkey = sign_hash(txhash,privkey,double_sha256(hexlify_(os.urandom(32),64)),True)
        uncompressedpubkey = uncompress_pubkey(compressedpubkey)
        newsig = str(newsig + str("01")) # add SIGHASH_ALL to end of sig
        try:
            num_sigs_req, pubkeylist = self.validate_redeem_script_and_return_keys(self.inputs[tx_input_num][3])
        except:
            raise Exception("Error validating redeem script for input that is attempting to be signed.")
        if compressedpubkey in pubkeylist:
            self.sigs[tx_input_num].append(str(newsig))
            self.sigspubkeylist[tx_input_num].append(str(compressedpubkey))
            self.sort_multisig_input_sigs_and_keys_to_redeemscript_order(tx_input_num)
        elif uncompressedpubkey in pubkeylist:
            self.sigs[tx_input_num].append(str(newsig))
            self.sigspubkeylist[tx_input_num].append(str(uncompressedpubkey))
            self.sort_multisig_input_sigs_and_keys_to_redeemscript_order(tx_input_num)
        else:
            raise Exception("Signature key does not appear to be in redeemscript list of keys.")
        self.update_tx_with_sigs()

    @staticmethod
    def validate_redeem_script_and_return_keys(redeemscript):
        redeemscript = str(str(redeemscript).lower())
        if len(redeemscript) > 1040:
            raise Exception("Redeem scripts must be less than or equal to 520 bytes.")
        if redeemscript[-2:] != "ae":
            raise Exception("Last byte in redeem script must be OP_EQUAL.  Only multisig redeem scripts are acceptable as inputs. This class is called 'SimpleBitcoinTx', emphasis on 'simple'.")
        if not (((int(redeemscript[:2],16) - 80) > 1 and (int(redeemscript[:2],16) - 80) < 16)):
            raise Exception("Redeem script must be a [2-15]-of-[2-15] multisig address. This class is called 'SimpleBitcoinTx', emphasis on 'simple'.")
        if not (((int(redeemscript[-4:-2],16) - 80) > 1 and (int(redeemscript[-4:-2],16) - 80) < 16)):
            raise Exception("Redeem script must be a [2-15]-of-[2-15] multisig address. This class is called 'SimpleBitcoinTx', emphasis on 'simple'.")
        if ((int(redeemscript[:2],16) - 80) > (int(redeemscript[-4:-2],16) - 80)):
            raise Exception("m cannot be greater than n in an m-of-n tx.")
        tempscripttest = str(redeemscript)[2:-4]
        counter = 0
        pubkeylist = []
        while True:
            if len(tempscripttest) == 0:
                break
            if tempscripttest[:2] == "21":
                pubkeylist.append(str(tempscripttest[2:68]))
                tempscripttest = str(tempscripttest)[68:]
            elif tempscripttest[:2] == "41":
                pubkeylist.append(str(tempscripttest[2:132]))
                tempscripttest = str(tempscripttest)[132:]
            else:
                raise Exception("Invalid public key in redeem script or other error.")
            counter = counter + 1
        assert counter == int(redeemscript[-4:-2],16) - 80
        assert counter == len(pubkeylist)
        return int(int(redeemscript[:2],16) - 80), pubkeylist

    def sort_multisig_input_sigs_and_keys_to_redeemscript_order(self,tx_input_num):
        redeemscript = str(self.inputs[tx_input_num][3])
        tx_input_num = int(tx_input_num)
        unsorted_pubkeylist = []
        for item in self.sigspubkeylist[tx_input_num]:
            unsorted_pubkeylist.append(str(item))
        try:
            x, sortedpubkeylist = validate_redeem_script_and_return_keys(redeemscript)
        except Exception as e:
            raise Exception(str(e))
        else:
            if len(self.sigs[tx_input_num]) > x or len(self.sigspubkeylist[tx_input_num]) > x:
                raise Exception("Length of sig list or pubkey list greater than m for redeem script.")
        newsortedsiglist = []
        newsortedpubkeylist = []
        for i in range(len(sortedpubkeylist)):
            if sortedpubkeylist[i] in unsorted_pubkeylist:
                itemindex = int(unsorted_pubkeylist.index(sortedpubkeylist[i]))
                newsortedsiglist.append(str(self.sigs[tx_input_num][itemindex]))
                newsortedpubkeylist.append(str(self.sigspubkeylist[tx_input_num][itemindex]))
        assert len(self.sigspubkeylist[tx_input_num]) == len(self.sigs[tx_input_num])
        listlen = len(self.sigs[tx_input_num])
        for i in range(listlen):
            del self.sigs[tx_input_num][i]
            del self.sigspubkeylist[tx_input_num][i]
        assert len(self.sigspubkeylist[tx_input_num]) == 0
        assert len(self.sigs[tx_input_num]) == 0
        assert len(newsortedsiglist) == len(newsortedpubkeylist)
        for i in range(len(newsortedsiglist)):
            self.sigs[tx_input_num].append(str(newsortedsiglist[i]))
            self.sigspubkeylist[tx_input_num].append(str(newsortedpubkeylist[i]))
        for i in range(x - len(self.sigs[tx_input_num])):
            self.sigs[tx_input_num].append(str(""))
            self.sigspubkeylist[tx_input_num].append(str(""))
        assert len(self.sigspubkeylist[tx_input_num]) == len(self.sigs[tx_input_num])
        assert len(self.sigspubkeylist) == len(self.sigs)
        x, sortedpubkeylist, newsortedsiglist, newsortedpubkeylist, unsorted_pubkeylist = None, None, None, None, None

    def update_tx_with_sigs(self):
        assert len(self.sigs) == len(self.sigspubkeylist)
        assert len(self.inputs) != 0
        assert len(self.outputs) != 0
        assert len(self.unsignedtx) != 0 and self.unsignedtx != ""
        self.partialtx = str(self.versionhex) + str(SimpleBitcoinTx.varint_bytesize(len(self.inputs)))
        for i in range(len(self.inputs)):
            self.partialtx = str(self.partialtx) + str(reverse_bytes(self.inputs[i][0])) + str(reverse_bytes(hexlify_(int(self.inputs[i][1]),8)))
            if self.inputs[i][2][:6] == "76a914" and len(self.inputs[i][2]) == 50:
                if self.sigs[i] == "":
                    self.partialtx = str(self.partialtx) + str("00")
                else:
                    siglen = SimpleBitcoinTx.varint_bytesize(int(len(self.sigs[i]) // 2))
                    pubkeylen = SimpleBitcoinTx.varint_bytesize(int(len(self.sigspubkeylist[i]) // 2))
                    inputstr = str(siglen) + str(self.sigs[i]) + str(pubkeylen) + str(self.sigspubkeylist[i])
                    inputstrlen = SimpleBitcoinTx.varint_bytesize(int(len(inputstr) // 2))
                    self.partialtx = str(self.partialtx) + str(inputstrlen) + str(inputstr)
            elif self.inputs[i][2][:4] == "a914" and len(self.inputs[i][2]) == 46:
                #add 00 for extra checkmultisigverify byte
                sigs_and_redeemscript = str("")
                hasonesig = False
                for j in len(self.sigs[i]):
                    if self.sigs[i][j] == "":
                        continue
                    hasonesig = True
                    siglen = SimpleBitcoinTx.varint_bytesize(int(len(str(self.sigs[i][j])) // 2))
                    sigs_and_redeemscript = str(sigs_and_redeemscript) + str(siglen) + str(self.sigs[i][j])
                if not hasonesig:
                    self.partialtx = str(self.partialtx) + str("00")
                else:
                    assert self.inputs[i][3] != ""
                    rs_len = SimpleBitcoinTx.varint_bytesize(int(len(str(self.inputs[i][3])) // 2))
                    sigs_and_redeemscript = str(sigs_and_redeemscript) + str("4c") + str(rs_len) + str(self.inputs[i][3])
                    sigs_and_redeemscript = str("00") + str(sigs_and_redeemscript) # for bug where OP_CHECKMULTISIG drops an extra byte
                    srs_len = SimpleBitcoinTx.varint_bytesize(int(len(str(sigs_and_redeemscript)) // 2))
                    self.partialtx = str(self.partialtx) + str(srs_len) + str(sigs_and_redeemscript)
            else:
                raise Exception("Error with inputs.")
            sequencebytes = hexlify_(self.inputs[i][4],8)
            assert len(sequencebytes) == 8
            sequencebytes = reverse_bytes(sequencebytes)
            self.partialtx = str(self.partialtx) + str(sequencebytes)
        self.partialtx = str(self.partialtx) + str(SimpleBitcoinTx.varint_bytesize(int(len(self.outputs))))
        for i in range(len(self.outputs)):
            if self.outputs[i][0][:1] == "1":
                amountinsatoshis = int(round(self.outputs[i][1],8) * 100000000)
                amountinsatoshis = hexlify_(amountinsatoshis,16)
                amountinsatoshis = reverse_bytes(amountinsatoshis)
                assert len(str(amountinsatoshis)) == 16
                self.partialtx = str(self.partialtx) + str(amountinsatoshis)
                outhex, isValid = base58_decode(str(self.outputs[i][0]),True,False)
                if not isValid or outhex[:2] != "00":
                    raise Exception("Base58 decoding error for output number " + str(i) + " when attempting to decode.  Checksum mis-match or other error.")
                outhex = str(outhex)[2:]
                assert len(outhex) == 40
                outhex_len = str(SimpleBitcoinTx.varint_bytesize(int(len(outhex) // 2)))
                assert outhex_len == "14"
                asm_len = str(SimpleBitcoinTx.varint_bytesize(int(len(str(str("76a9") + str(outhex_len) + str(outhex) + str("88ac"))) // 2)))
                assert asm_len == "19"
                self.partialtx = str(self.partialtx) + str(asm_len) + str("76a9") + str(outhex_len) + str(outhex) + str("88ac")
            elif self.outputs[i][0][:1] == "3":
                amountinsatoshis = int(round(self.outputs[i][1],8) * 100000000)
                amountinsatoshis = hexlify_(amountinsatoshis,16)
                amountinsatoshis = reverse_bytes(amountinsatoshis)
                assert len(str(amountinsatoshis)) == 16
                self.partialtx = str(self.partialtx) + str(amountinsatoshis)
                outhex, isValid = base58_decode(str(self.outputs[i][0]),True,False)
                if not isValid or outhex[:2] != "05":
                    raise Exception("Base58 decoding error for output number " + str(i) + " when attempting to decode.  Checksum mis-match or other error.")
                outhex = str(outhex)[2:]
                assert len(outhex) == 40
                outhex_len = str(SimpleBitcoinTx.varint_bytesize(int(len(outhex) // 2)))
                assert outhex_len == "14"
                asm_len = str(SimpleBitcoinTx.varint_bytesize(int(len(str(str("a9") + str(outhex_len) + str(outhex) + str("87"))) // 2)))
                assert asm_len == "17"
                self.partialtx = str(self.partialtx) + str(asm_len) + str("a9") + str(outhex_len) + str(outhex) + str("87")
            elif self.outputs[i][0] == "OP_RETURN":
                self.partialtx = str(self.partialtx) + str("0000000000000000")
                opreturnhex = str(self.outputs[i][1])
                try:
                    opreturnhex = hexlify_(binascii.unhexlify(opreturnhex))
                except:
                    raise Exception("Unknown error with OP_RETURN data on input " + str(i))
                opreturnlen1 = str(SimpleBitcoinTx.varint_bytesize(int(len(opreturnhex) // 2)))
                opreturn = str("6a") + str(opreturnlen) + str(opreturnhex)
                opreturnlen2 = str(SimpleBitcoinTx.varint_bytesize(int(len(opreturn) // 2)))
                self.partialtx = str(self.partialtx) + str(opreturnlen2) + str(opreturn)
        self.partialtx = str(self.partialtx) + self.nlocktime
        self.partialtx = str(self.partialtx)
        iscomplete = True
        for i in range(len(self.sigs)):
            if 'list' not in str(type(self.sigs[i])):
                if self.sigs[i] == "":
                    iscomplete = False
                    break
            else:
                for j in range(len(self.sigs[i])):
                    if self.sigs[i][j] == "":
                        iscomplete = False
                        break
                if not iscomplete:
                    break
        if iscomplete:
            self.finaltx = str(self.partialtx)
            self.txid = str(reverse_bytes(double_sha256(self.finaltx)))
        else:
            self.finaltx = str("")
            self.txid = str("INCOMPLETE")

    @staticmethod
    def download_tx_hex_from_id(txid):
        txid = str(txid)
        try:
            txid = hexlify_(binascii.unhexlify(txid))
            assert len(txid) == 64
        except:
            raise Exception("Error with txid input.")
        ### ### ### ### ### ### ### ###
        # For now, we're just downloading it from a website block explorer, but you could easily write a localhost/bitcoind call here.
        try:
            import urllib2
            output = str(urllib2.urlopen(str(str("https://blockchain.info/tx/") + str(txid) + str("?format=hex"))).read())
        except:
            raise Exception("Error downloading tx from web.")
        if "Transaction not found" in output or len(output) < 32:
            raise Exception("Tx ID does not exist.")
        ### ### ### ### ### ### ### ###
        return str(output)

    @staticmethod
    def return_int_from_varint_bytes(varintbytes):
        varintbytes = str(varintbytes)
        if varintbytes[:2] == "ff":
            assert len(varintbytes) == 18
            len_bytes = reverse_bytes(varintbytes[2:])
            outputlen = int(len_bytes,16)
        elif varintbytes[:2] == "fe":
            assert len(varintbytes) == 10
            len_bytes = reverse_bytes(varintbytes[2:])
            outputlen = int(len_bytes,16)
        elif varintbytes[:2] == "fd":
            assert len(varintbytes) == 6
            len_bytes = reverse_bytes(varintbytes[2:])
            outputlen = int(len_bytes,16)
        else:
            assert len(varintbytes) == 2
            outputlen = int(varintbytes,16)
        return int(outputlen)

    @staticmethod
    def get_asm_and_amount_satoshis_from_tx_hex(fulltx,vout):
        try:
            fulltx = hexlify_(binascii.unhexlify(fulltx))
            assert len(fulltx) > 64
        except:
            raise Exception("Input tx must be hex formatted tx. (And not tx ID.)")
        try:
            vout = int(vout)
        except:
            raise Exception("vout must be an int")
        remainingtx = str(fulltx)
        remainingtx = remainingtx[8:] # strip version
        if remainingtx[:2] == "ff":
            num_inputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
            remainingtx = remainingtx[18:]
        elif remainingtx[:2] == "fe":
            num_inputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
            remainingtx = remainingtx[10:]
        elif remainingtx[:2] == "fd":
            num_inputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
            remainingtx = remainingtx[6:]
        else:
            num_inputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
            remainingtx = remainingtx[2:]
        for i in range(num_inputs):
            remainingtx = remainingtx[72:] # strip tx ID and vout num
            if remainingtx[:2] == "00":
                remainingtx = remainingtx[2:]
            else:
                if remainingtx[:2] == "ff":
                    inputlen = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
                    remainingtx = remainingtx[18:]
                elif remainingtx[:2] == "fe":
                    inputlen = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
                    remainingtx = remainingtx[10:]
                elif remainingtx[:2] == "fd":
                    inputlen = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
                    remainingtx = remainingtx[6:]
                else:
                    inputlen = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
                    remainingtx = remainingtx[2:]
                inputlen = inputlen * 2
                remainingtx = remainingtx[inputlen:] # strip entire input
                remainingtx = remainingtx[8:] # strip sequence
        if remainingtx[:2] == "ff":
            numoutputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
            remainingtx = remainingtx[18:]
        elif remainingtx[:2] == "fe":
            numoutputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
            remainingtx = remainingtx[10:]
        elif remainingtx[:2] == "fd":
            numoutputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
            remainingtx = remainingtx[6:]
        else:
            numoutputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
            remainingtx = remainingtx[2:]
        for i in range(numoutputs):
            curr_satoshiamount = int(reverse_bytes(remainingtx[:16]),16)
            remainingtx = remainingtx[16:]
            if remainingtx[:2] == "ff":
                newasmlen = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
                remainingtx = remainingtx[18:]
            elif remainingtx[:2] == "fe":
                newasmlen = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
                remainingtx = remainingtx[10:]
            elif remainingtx[:2] == "fd":
                newasmlen = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
                remainingtx = remainingtx[6:]
            else:
                newasmlen = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
                remainingtx = remainingtx[2:]
            newasmlen = newasmlen * 2
            newasm = remainingtx[:newasmlen]
            remainingtx = remainingtx[newasmlen:]
            if i == vout:
                return str(newasm), int(curr_satoshiamount)
        raise Exception("vout input number is greater than number of outputs in tx")

    def breakdown_tx(self, importedredeemscripts):
        importedredeemscripts = importedredeemscripts
        remainingtx = str(self.input_tx)
        self.versionhex = str(self.input_tx)[:8]
        self.txversion = int(reverse_bytes(self.versionhex),16)
        remainingtx = remainingtx[8:]
        if remainingtx[:2] == "ff":
            num_inputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
            remainingtx = remainingtx[18:]
        elif remainingtx[:2] == "fe":
            num_inputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
            remainingtx = remainingtx[10:]
        elif remainingtx[:2] == "fd":
            num_inputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
            remainingtx = remainingtx[6:]
        else:
            num_inputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
            remainingtx = remainingtx[2:]
        for i in range(num_inputs):
            txid = reverse_bytes(remainingtx[:64])
            remainingtx = remainingtx[64:]
            if remainingtx[:2] == "ff":
                vout = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
                remainingtx = remainingtx[18:]
            elif remainingtx[:2] == "fe":
                vout = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
                remainingtx = remainingtx[10:]
            elif remainingtx[:2] == "fd":
                vout = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
                remainingtx = remainingtx[6:]
            else:
                vout = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
                remainingtx = remainingtx[2:]
            asm_hex, xamount = SimpleBitcoinTx.get_asm_and_amount_satoshis_from_tx_hex(SimpleBitcoinTx.download_tx_hex_from_id(txid),vout)
            if asm_hex[:4] == "a914" and len(asm_hex) == 46 and asm_hex[-2:] == "87":
                if remainingtx[:2] == "00":
                    if len(importedredeemscripts) == 0:
                        raise Exception("Cannot import tx with unsigned multisig inputs without redeem script.")
                    redeemscript = hexlify_(binascii.unhexlify(importedredeemscripts[0]))
                    del importedredeemscripts[0]
                    try:
                        num_sigs, pubkeylist = SimpleBitcoinTx.validate_redeem_script_and_return_keys(redeemscript)
                        try:
                            del pubkeylist
                        except:
                            pubkeylist = []
                    except:
                        raise Exception("Invalid redeem script given for input.")
                    assert hash160(redeemscript) == asm_hex[4:-2] # List of redeem scripts must be given in order of multisig inputs
                    self.inputs.append([txid,vout,asm_hex,redeemscript,int(reverse_bytes(remainingtx[2:10]),16)])
                    remainingtx = remainingtx[10:]
                    self.sigs.append([])
                    self.sigspubkeylist.append([])
                    for j in range(num_sigs):
                        self.sigs[-1].append(str(""))
                        self.sigspubkeylist[-1].append(str(""))
                else:
                    if remainingtx[:2] == "ff":
                        sigs_and_script_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
                        remainingtx = remainingtx[18:]
                    elif remainingtx[:2] == "fe":
                        sigs_and_script_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
                        remainingtx = remainingtx[10:]
                    elif remainingtx[:2] == "fd":
                        sigs_and_script_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
                        remainingtx = remainingtx[6:]
                    else:
                        sigs_and_script_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
                        remainingtx = remainingtx[2:]
                    sigs_and_script_len = sigs_and_script_len * 2 # Working with strings so each byte of hex is 2 chars
                    assert remainingtx[:2] == "00" # OP_CHECKMULTISIG extra byte
                    remainingtx = remainingtx[2:]
                    current_siglist = []
                    while remainingtx[:2] != "4c": # Is there another way to tell when sigs list is finished??
                        len_curr_sig = int(remainingtx[:2],16) * 2 # Even if this is a varint, the length of the sig should never be more than 1 byte
                        remainingtx = remainingtx[2:]
                        curr_sig = remainingtx[:len_curr_sig]
                        current_siglist.append(str(curr_sig))
                        remainingtx = remainingtx[len_curr_sig:]
                    assert remainingtx[:2] == "4c"
                    remainingtx = remainingtx[2:]
                    if remainingtx[:2] == "ff":
                        len_redeemscript = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
                        remainingtx = remainingtx[18:]
                    elif remainingtx[:2] == "fe":
                        len_redeemscript = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
                        remainingtx = remainingtx[10:]
                    elif remainingtx[:2] == "fd":
                        len_redeemscript = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
                        remainingtx = remainingtx[6:]
                    else:
                        len_redeemscript = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
                        remainingtx = remainingtx[2:]
                    len_redeemscript = len_redeemscript * 2
                    redeemscript = remainingtx[:len_redeemscript]
                    remainingtx = remainingtx[len_redeemscript:]
                    try:
                        num_sigs, pubkeylist = SimpleBitcoinTx.validate_redeem_script_and_return_keys(redeemscript)
                    except:
                        raise Exception("Invalid redeem script detected, or other error with tx.  Please make sure to only import simple standard tx's.  This module will error with complicated tx's.")
                    sequence = int(reverse_bytes(remainingtx[:8]),16)
                    remainingtx = remainingtx[8:]
                    self.inputs.append([txid,vout,asm_hex,redeemscript,sequence])
                    self.sigs.append([])
                    self.sigspubkeylist.append([])
                    for j in range(len(current_siglist)):
                        self.sigs[i].append(str(current_siglist[j]))
                        # Must append pubkeylist later, since you can only figure out which keys to add by knowing the rest of the tx.
            elif asm_hex[:6] == "76a914" and len(asm_hex) == 50 and asm_hex[-4:] == "88ac":
                if remainingtx[:2] == "00":
                    self.inputs.append([txid,vout,asm_hex,"",int(reverse_bytes(remainingtx[2:10]),16)])
                    self.sigs.append(str(""))
                    self.sigspubkeylist.append(str(""))
                    remainingtx = remainingtx[10:]
                else:
                    if remainingtx[:2] == "ff":
                        sigpub_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
                        remainingtx = remainingtx[18:]
                    elif remainingtx[:2] == "fe":
                        sigpub_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
                        remainingtx = remainingtx[10:]
                    elif remainingtx[:2] == "fd":
                        sigpub_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
                        remainingtx = remainingtx[6:]
                    else:
                        sigpub_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
                        remainingtx = remainingtx[2:]
                    sigpub_len = sigpub_len * 2 # Working with strings so each byte of hex is 2 chars
                    if remainingtx[:2] == "ff":
                        sig_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
                        remainingtx = remainingtx[18:]
                    elif remainingtx[:2] == "fe":
                        sig_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
                        remainingtx = remainingtx[10:]
                    elif remainingtx[:2] == "fd":
                        sig_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
                        remainingtx = remainingtx[6:]
                    else:
                        sig_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
                        remainingtx = remainingtx[2:]
                    sig_len = sig_len * 2 # Working with strings so each byte of hex is 2 chars
                    sig = remainingtx[:sig_len]
                    remainingtx = remainingtx[sig_len:]
                    assert sig[-2:] == "01" # Only allowing SIGHASH_ALL at this point. Remember this class's name! Simple!!!
                    if remainingtx[:2] == "ff":
                        pubkey_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
                        remainingtx = remainingtx[18:]
                    elif remainingtx[:2] == "fe":
                        pubkey_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
                        remainingtx = remainingtx[10:]
                    elif remainingtx[:2] == "fd":
                        pubkey_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
                        remainingtx = remainingtx[6:]
                    else:
                        pubkey_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
                        remainingtx = remainingtx[2:]
                    pubkey_len = pubkey_len * 2 # Working with strings so each byte of hex is 2 chars
                    pubkey = remainingtx[:pubkey_len]
                    remainingtx = remainingtx[pubkey_len:]
                    sequence = int(reverse_bytes(remainingtx[:8]),16)
                    remainingtx = remainingtx[8:]
                    self.inputs.append([str(txid),int(vout),str(asm_hex),str(""),int(sequence)])
                    self.sigs.append(str(sig))
                    self.sigspubkeylist.append(str(pubkey))
            else:
                raise Exception("Only bitcoin addresses and multisig addresses are allowed as inputs.")
        if remainingtx[:2] == "ff":
            num_outputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
            remainingtx = remainingtx[18:]
        elif remainingtx[:2] == "fe":
            num_outputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
            remainingtx = remainingtx[10:]
        elif remainingtx[:2] == "fd":
            num_outputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
            remainingtx = remainingtx[6:]
        else:
            num_outputs = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
            remainingtx = remainingtx[2:]
        for i in range(num_outputs):
            amount = float(float(int(reverse_bytes(remainingtx[:16]),16)) / 100000000.0)
            remainingtx = remainingtx[16:]
            if remainingtx[:2] == "ff":
                asm_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:18])
                remainingtx = remainingtx[18:]
            elif remainingtx[:2] == "fe":
                asm_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:10])
                remainingtx = remainingtx[10:]
            elif remainingtx[:2] == "fd":
                asm_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:6])
                remainingtx = remainingtx[6:]
            else:
                asm_len = SimpleBitcoinTx.return_int_from_varint_bytes(remainingtx[:2])
                remainingtx = remainingtx[2:]
            asm_len = asm_len * 2
            curr_asm = remainingtx[:asm_len]
            remainingtx = remainingtx[asm_len:]
            if curr_asm[:6] == "76a914" and len(curr_asm) == 50 and curr_asm[-4:] == "88ac":
                curr_address = base58_check_and_encode("00" + curr_asm[6:-4])
                assert curr_address[:1] == "1"
                self.add_output(str(curr_address),amount)
            elif curr_asm[:4] == "a914" and len(curr_asm) == 46 and curr_asm[-2:] == "87":
                curr_address = base58_check_and_encode("05" + curr_asm[4:-2])
                assert curr_address[:1] == "3"
                self.add_output(str(curr_address),amount)
            elif curr_asm[:2] == "6a":
                curr_asm = curr_asm[2:]
                if curr_asm[:2] == "ff":
                    curr_asm_len = SimpleBitcoinTx.return_int_from_varint_bytes(curr_asm[:18])
                    curr_asm = curr_asm[18:]
                elif curr_asm[:2] == "fe":
                    curr_asm_len = SimpleBitcoinTx.return_int_from_varint_bytes(curr_asm[:10])
                    curr_asm = curr_asm[10:]
                elif curr_asm[:2] == "fd":
                    curr_asm_len = SimpleBitcoinTx.return_int_from_varint_bytes(curr_asm[:6])
                    curr_asm = curr_asm[6:]
                else:
                    curr_asm_len = SimpleBitcoinTx.return_int_from_varint_bytes(curr_asm[:2])
                    curr_asm = curr_asm[2:]
                assert len(curr_asm) == curr_asm_len * 2
                self.add_output(str("OP_RETURN"),str(curr_asm))
            else:
                raise Exception("Unknown output types.  Cannot import tx!  Remember, this class is for SIMPLE Bitcoin tx's.")
        assert len(remainingtx) == 8
        self.set_nlocktime(int(reverse_bytes(remainingtx),16))
        self.serialize_to_unsigned_tx()
        # Now that the tx is mostly complete, check for multisig signatures and verify public keys from redeem script, and add keys which go with a sig to the self.sigspubkeylist
        # First we count how many multisig inputs we have
        # Then for each multisig, we have to reconstruct the tx, so we can get the data to verify the multisig sigs with.
        num_multisig_inputs = 0
        for i in range(len(self.inputs)):
            if self.inputs[i][2][:4] == "a914":
                num_multisig_inputs = num_multisig_inputs + 1
        if num_multisig_inputs == 0:
            self.update_tx_with_sigs()
            return
        num_multisig_inputs_checked_so_far = 0
        for i in range(num_multisig_inputs):
            #First we reconstruct the tx
            reconstructedtx = self.versionhex
            reconstructedtx = reconstructedtx + SimpleBitcoinTx.varint_bytesize(num_inputs)
            for j in range(len(self.inputs)):
                reconstructedtx = reconstructedtx + reverse_bytes(self.inputs[j][0])
                reconstructedtx = reconstructedtx + reverse_bytes(hexlify_(self.inputs[j][1],8))
                if self.inputs[j][2][:4] == "a914" and i == num_multisig_inputs_checked_so_far:
                    assert len(self.inputs[j][3]) != 0
                    rs_len = SimpleBitcoinTx.varint_bytesize(int(len(self.inputs[j][3]) / 2))
                    reconstructedtx = reconstructedtx + rs_len + str(self.inputs[j][3])
                else:
                    reconstructedtx = reconstructedtx + str("00")
                reconstructedtx = reconstructedtx + reverse_bytes(hexlify_(int(self.inputs[j][4]),8))
            reconstructedtx = reconstructedtx + SimpleBitcoinTx.varint_bytesize(num_outputs)
            for j in range(num_outputs):
                if self.outputs[j][0][:1] == "1":
                    amountsatoshis = reverse_bytes(hexlify_(int(float(self.outputs[j][1]) * 100000000),16))
                    reconstructedtx = reconstructedtx + str(amountsatoshis)
                    try:
                        new_asm, isValid = base58_decode(self.outputs[j][0],True,False)
                        if not isValid:
                            raise Exception("Base58 checksum mis-match on output " + str(j) + " while attempting to reconstruct imported tx for checking multisig keys.")
                    except Exception as e:
                        raise Exception(str(e))
                    assert new_asm[:2] == "00"
                    new_asm = str(new_asm[2:])
                    assert len(new_asm) == 40
                    new_asm = str(str("76a914") + new_asm + str("88ac"))
                elif self.outputs[j][0][:1] == "3":
                    amountsatoshis = reverse_bytes(hexlify_(int(float(self.outputs[j][1]) * 100000000),16))
                    reconstructedtx = reconstructedtx + str(amountsatoshis)
                    try:
                        new_asm, isValid = base58_decode(self.outputs[j][0],True,False)
                        if not isValid:
                            raise Exception("Base58 checksum mis-match on output " + str(j) + " while attempting to reconstruct imported tx for checking multisig keys.")
                    except Exception as e:
                        raise Exception(str(e))
                    assert new_asm[:2] == "05"
                    new_asm = str(new_asm[2:])
                    assert len(new_asm) == 40
                    new_asm = str(str("a914") + new_asm + str("87"))
                elif self.outputs[j][0] == "OP_RETURN":
                    reconstructedtx = reconstructedtx + str("0000000000000000")
                    new_asm = str(self.outputs[j][1])
                    opreturn_len = str(SimpleBitcoinTx.varint_bytesize(int(len(new_asm) / 2)))
                    new_asm = str("6a") + opreturn_len + new_asm
                else:
                    raise Exception("Problem with output number " + str(j) + " in imported tx while verifying multisig keys.")
                new_asm_len = str(SimpleBitcoinTx.varint_bytesize(int(len(new_asm) / 2)))
                new_asm = str(new_asm_len + new_asm)
                reconstructedtx = str(reconstructedtx + new_asm_len + new_asm)
            reconstructedtx = reconstructedtx + self.nlocktime
            reconstructedtx = str(reconstructedtx + str("01000000"))
            # Tx reconstruction complete. Now we check multisig signatures against keys, and add keys to keylist if they verify
            curr_multisig_counter = 0
            for j in range(len(self.inputs)):
                if self.inputs[j][2][:4] == "a914":
                    if curr_multisig_counter == num_multisig_inputs_checked_so_far:
                        numkeys, newpubkeylist = SimpleBitcoinTx.validate_redeem_script_and_return_keys(self.inputs[j][3])
                        for k in range(len(self.sigs[j])):
                            lennewpubkeylist = len(newpubkeylist)
                            for l in range(lennewpubkeylist):
                                testvalidation = verify_sig(double_sha256(reconstructedtx),self.sigs[j][k],newpubkeylist[0])
                                if testvalidation:
                                    self.sigspubkeylist[j].append(str(newpubkeylist[0]))
                                del newpubkeylist[0]
            num_multisig_inputs_checked_so_far = num_multisig_inputs_checked_so_far + 1
        # Now that we've got a complete sig list as well as which keys go with which multisig sigs, we can update the tx and fill in the blanks for all the class variables.
        self.update_tx_with_sigs()

    def __str__(self):
        if self.finaltx and self.finaltx != "":
            return str(self.finaltx)
        elif self.partialtx and self.partialtx != "":
            return str(self.partialtx)
        else:
            return str(self.unsignedtx)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
