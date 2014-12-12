#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Relative import off for doctests
# from hexlify_permissive import *
# from hash_funcs import *

from .hexlify_permissive import *
from .hash_funcs import *

def normalize_input(input):
    input = str(input)
    if int(sys.version_info.major) == 2:
        input = unicode(input)
    input = str(unicodedata.normalize('NFC',input))
    return str(input)

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

def bytesize_to_varint(inputhex):
    """
    Outputs two ints: first is the integer byte size indicated by the varint bytes, and the second is the total length of the varint bytes, so you know how much to cut off after you have read the data.
    """
    try:
        inputhex = hexlify_(unhexlify_(inputhex))
        test2 = int(inputhex,16)
        test2 = None
    except:
        raise TypeError("Input must be hex")
    assert not len(inputhex) % 2
    if inputhex[:2] == "ff":
        if len(inputhex) < 18:
            raise Exception("Input size byte is 0xff which indicates 8 bytes follow it, but the length of the input is less than that.  Please input at least the full varint bytes -- or longer to be safe.  This function will simply read the correct amount off the front.")
        outputint = int(reverse_bytes(inputhex[2:18]),16)
        byte_len_to_trim_incl_firstbyte = int(9)
    elif inputhex[:2] == "fe":
        if len(inputhex) < 10:
            raise Exception("Input size byte is 0xfe which indicates 4 bytes follow it, but the length of the input is less than that.  Please input at least the full varint bytes -- or longer to be safe.  This function will simply read the correct amount off the front.")
        outputint = int(reverse_bytes(inputhex[2:10]),16)
        byte_len_to_trim_incl_firstbyte = int(5)
    elif inputhex[:2] == "fd":
        if len(inputhex) < 6:
            raise Exception("Input size byte is 0xfd which indicates 2 bytes follow it, but the length of the input is less than that.  Please input at least the full varint bytes -- or longer to be safe.  This function will simply read the correct amount off the front.")
        outputint = int(reverse_bytes(inputhex[2:6]),16)
        byte_len_to_trim_incl_firstbyte = int(3)
    else:
        outputint = int(inputhex[:2],16)
        byte_len_to_trim_incl_firstbyte = int(1)
    return int(outputint), int(byte_len_to_trim_incl_firstbyte)

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

if __name__ == "__main__":
    import doctest
    doctest.testmod()
