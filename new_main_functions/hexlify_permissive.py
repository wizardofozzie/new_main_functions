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

if __name__ == "__main__":
    import doctest
    doctest.testmod()
