#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hexlify_permissive import *

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

if __name__ == "__main__":
    import doctest
    doctest.testmod()
