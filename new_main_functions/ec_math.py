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
H_COFACTOR = 1 # 0x01
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

if __name__ == "__main__":
    import doctest
    doctest.testmod()
