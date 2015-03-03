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
    def asset_address_from_privkey(privkey,compressed=False):
        privkey, compress_ = privkey_to_hexstr(privkey,True)
        if compress_ != -1:
            if compress_ == 1:
                compressed = True
            else:
                compressed = False
        addr = "1300" + hash160(privkey_to_pubkey(privkey,compressed))
        return base58_check_and_encode(addr)

    @staticmethod
    def asset_address_from_bitcoin_address(bitcoinaddr):
        bitcoinhex, isValid = base58_decode(bitcoinaddr,True,False)
        if not isValid:
            raise Exception("Base58 checksum does not match on input Bitcoin address.")
        assert bitcoinhex[:2] == "00"
        assetaddr = str("13" + str(bitcoinhex))
        return base58_check_and_encode(assetaddr)

    @staticmethod
    def assetID_from_redeemscript(redeemscript):
        # This is my own proposal, it is NOT part of the OA standard.
        # https://github.com/7trXMk6Z/openassets_expansion_proposals/blob/master/oamultisig.mediawiki
        redeemscript = hexlify_(binascii.unhexlify(redeemscript))
        scriptpubkey = str("a914" + hash160(redeemscript) + "87")
        assetID = str("1c" + hash160(scriptpubkey))
        return base58_check_and_encode(assetID)

    @staticmethod
    def asset_address_from_redeemscript(redeemscript):
        # This is my own proposal, it is NOT part of the OA standard.
        # https://github.com/7trXMk6Z/openassets_expansion_proposals/blob/master/oamultisig.mediawiki
        return base58_check_and_encode(str("1405" + hash160(hexlify_(binascii.unhexlify(redeemscript)))))

    @staticmethod
    def asset_address_from_P2SH_address(addr):
        # This is my own proposal, it is NOT part of the OA standard.
        # https://github.com/7trXMk6Z/openassets_expansion_proposals/blob/master/oamultisig.mediawiki
        addrhex, isValid = base58_decode(addr,True,False)
        if not isValid:
            raise Exception("Base58 checksum does not match on input P2SH address.")
        assert addrhex[:2] == "05"
        return base58_check_and_encode(str("14" + str(addrhex)))

    @staticmethod
    def multiple_unsigned_LEB128_to_int_list(LEBinput, assetquantitycount_int, outputbytelen=False):
        # Hex len can be greater than or equal to the required amount.  If it's greater, the script will still process it correctly, and that's what the outputbytelen is for -- you can just input the entire hex, as long as it starts with LBE number(s), and use the byte len output to determine how much to trim.
        """
        >>> OpenAssets.multiple_unsigned_LEB128_to_int_list("ac0200e58e26",3)
        [300, 0, 624485]
        >>> OpenAssets.multiple_unsigned_LEB128_to_int_list("ac0200e58e26ac0200e58e26ac0200e58e26",3,True)
        ([300, 0, 624485], 6)
        >>> OpenAssets.multiple_unsigned_LEB128_to_int_list("ac0200e58e26ac0200e58e26ac0200e58e26",3,False)
        [300, 0, 624485]
        >>> OpenAssets.multiple_unsigned_LEB128_to_int_list("ac0200e58e26ac0200e58e26ac0200e58e26",1)
        [300]
        >>> OpenAssets.multiple_unsigned_LEB128_to_int_list("ac0200e58e26ac0200e58e26ac0200e58e26",1,True)
        ([300], 2)

        # Example from tx cc8cd7d92c6bf43738dae94ce7eccde5ce11b2829aac7c09d38a095621b45d44
        # OP_RETURN 4f41010001c0843d1b753d68747470733a2f2f6370722e736d2f5a78616f633973394149
        # Cut off 4f410100
        >>> script = "01c0843d1b753d68747470733a2f2f6370722e736d2f5a78616f633973394149"
        >>> assetquantitycount, trim = bytesize_to_varint(script) # bytesize_to_varint() also works with too much hex
        >>> script = script[trim*2:] # I use hexstr, hence multiply bytes to trim by 2
        >>> int_list, trim = OpenAssets.multiple_unsigned_LEB128_to_int_list(script,assetquantitycount,True)
        >>> asset_def_hex = script[trim*2:]
        >>> asset_def_bytesize, trim = bytesize_to_varint(asset_def_hex)
        >>> asset_def_hex = asset_def_hex[trim*2:]
        >>> int_list, asset_def_hex
        ([1000000], '753d68747470733a2f2f6370722e736d2f5a78616f633973394149')
        """

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

