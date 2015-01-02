#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Relative import off for doctests
# from ec_math import *
# from hexlify_permissive import *
# from hash_funcs import *
# from base58_hex_conversions import *
# from bitcoin_funcs import *
# from misc_funcs_and_vars import *
# from CoinFromKey import *

from .ec_math import *
from .hexlify_permissive import *
from .hash_funcs import *
from .base58_hex_conversions import *
from .bitcoin_funcs import *
from .misc_funcs_and_vars import *
from .CoinFromKey import *

class OpenAssets(object):

    @staticmethod
    def assetID_from_privkey(privkey,compressed=False):
        privkey, compress_ = privkey_to_hexstr(privkey,True)
        if compress_ != -1:
            if compress_ == 1:
                compressed = True
            else:
                compressed = False
        scriptpubkey = str("76a914" + hash160(privkey_to_pubkey(privkey,compressed)) + "88ac")
        assetID = str("17" + hash160(scriptpubkey))
        return base58_check_and_encode(assetID)

    @staticmethod
    def multiple_unsigned_LEB128_to_int_list(LEBinput, assetquantitycount_int, outputbytelen=False):
        try:
            LEBinput = hexlify_(binascii.unhexlify(LEBinput))
        except Exception as e:
            raise Exception("Input not hex. Exception raised was:  " + str(e))
        LEBlist = []
        LEBbytelen = 0
        tempbytes = str(LEBinput)
        for i in range(assetquantitycount_int):
            currbytes = str("")
            for j in range(len(tempbytes)):
                currbytes = currbytes + tempbytes[2*j:2*j + 2]
                if int(tempbytes[2*j:2*j + 2],16) < 128:
                    break
            try:
                LEBlist.append(unsigned_LEB128_to_int(currbytes))
            except:
                raise Exception("Hex input contains fewer LEB numbers than asset quantity input says should be there. (Input hex is too short.)")
            LEBbytelen = LEBbytelen + int(len(currbytes) / 2)
            tempbytes = tempbytes[len(currbytes):]
        assert len(LEBlist) == assetquantitycount_int
        if outputbytelen:
            return LEBlist, LEBbytelen
        else:
            return LEBlist

