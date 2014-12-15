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
# from StealthAddress import *
# from Bip32Key import *
# from BIP39 import *
# from ElectrumV1 import *
# from DER_sign_and_verify import *

from .ec_math import *
from .hexlify_permissive import *
from .hash_funcs import *
from .base58_hex_conversions import *
from .bitcoin_funcs import *
from .misc_funcs_and_vars import *
from .CoinFromKey import *
from .StealthAddress import *
from .Bip32Key import *
from .BIP39 import *
from .ElectrumV1 import *
from .DER_sign_and_verify import *

class SimpleBitcoinTx(object):
    """
    Create from scratch, or import and break down into component parts, a SIMPLE bitcoin transaction.  Emphasis on SIMPLE.  Acceptable address types for inputs and outputs are normal bitcoin addresses and multisig P2SH addresses (but only multisig, not other P2SH scripts).  Additionally, a single OP_RETURN output can be added.  No other types of things can be done.  This method doesn't check provided signatures (although it makes valid new ones for created tx's).  It will probably fail in edge cases and some regular testing.  I wrote it just to prove to myself I understood basically how transactions worked.  DO NOT USE THIS FOR ANYTHING IMPORTANT.

    WARNING:  Not all variables may be properly cleared when exceptions are raised, so if you run into an exception during use of this class, you must START A NEW ONE, DO NOT CONTINUE WITH THE SAME OBJECT.

    All those caveats and warnings aside, by god this sucker actually works.

    TODO:  Write doctests, check for bugs, fix bugs, reset relevant variables on exceptions, make sure doctests cover all use cases.
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

    def get_total_in(self):
        self.totalin = 0
        for i in range(len(self.inputs)):
            tempasm, amount = SimpleBitcoinTx.get_asm_and_amount_satoshis_from_tx_hex(self.inputs[i][0],self.inputs[i][1])
            tempasm = None
            self.totalin = self.totalin + amount
        self.totalin = round(float(self.totalin) / 100000000.0,8)
        tempstr = str(self.totalin)
        numzeros = 0
        while True:
            if tempstr[:-1] == "0" and numzeros < 9:
                numzeros = numzeros + 1
                tempstr = tempstr[:-1]
            else:
                break
        if numzeros == 8:
            self.totalin = int(self.totalin)
        else:
            self.totalin = round(self.totalin,8-numzeros)
        return self.totalin

    def get_total_out(self):
        self.totalout = 0
        for i in range(len(self.outputs)):
            if self.outputs[i][0] != "OP_RETURN":
                self.totalout = self.totalout + self.outputs[i][1]
        return self.totalout

    def get_fee(self):
        self.fee = self.get_total_in() - self.get_total_out()
        if self.fee < 0:
            self.fee = None
            raise Exception("Calculated fee amount is less than zero.  Please finish adding inputs and outputs before running this method.")
        elif self.fee > 0.01:
            self.fee = None
            raise Exception("Calculated fee amount is greater than 0.01 bitcoins.  Either a mistake has been made or you havne't finished adding outputs.  Please finish adding outputs and run this method again.")
        else:
            return self.fee

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
                assert binascii.unhexlify(redeemscript) == test
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
                m_num_keys, y = SimpleBitcoinTx.validate_redeem_script_and_return_keys(redeemscript)
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
                outputamount = round(float(tempvar2),8)
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
                outputamount = round(float(tempvar2),8)
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
        self.unsignedtx = str(self.versionhex) + str(varint_bytesize(len(self.inputs)))
        for i in range(len(self.inputs)):
            self.unsignedtx = self.unsignedtx + str(reverse_bytes(self.inputs[i][0]))
            assert len(str(reverse_bytes(hexlify_(int(self.inputs[i][1]),8)))) == 8
            self.unsignedtx = self.unsignedtx + str(reverse_bytes(hexlify_(int(self.inputs[i][1]),8)))
            self.unsignedtx = self.unsignedtx + str("00")
            assert len(str(reverse_bytes(hexlify_(int(self.inputs[i][4]),8)))) == 8
            self.unsignedtx = self.unsignedtx + str(reverse_bytes(hexlify_(int(self.inputs[i][4]),8)))
        self.unsignedtx = self.unsignedtx + str(varint_bytesize(len(self.outputs)))
        for i in range(len(self.outputs)):
            if self.outputs[i][0] == "OP_RETURN":
                lenopreturndata = str(varint_bytesize(int(len(self.outputs[i][1]) // 2)))
                outputstr = str("6a") + lenopreturndata + str(self.outputs[i][1]) # OP_RETURN + size of data + data
                totaloutputlen = str(varint_bytesize(int(len(outputstr) // 2)))
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
                    asm = str("a9") + str(varint_bytesize(int(len(outputhex[2:]) // 2))) + str(outputhex[2:]) + str("87") # OP_HASH160 .... OP_EQUAL
                elif outputhex[:2] == "00":
                    asm = str("76a9") + str(varint_bytesize(int(len(outputhex[2:]) // 2))) + str(outputhex[2:]) + str("88ac") # OP_DUP OP_HASH160 .... OP_EQUALVERIFY OP_CHECKSIG
                else:
                    self.unsignedtx = str("")
                    raise Exception("Output " + str(i) + " is not a recognized address. Only 1BitcoinAddress and 3PaytoScriptHash address formats are valid. This class is called 'SimpleBitcoinTx' for a reason!")
                asm = str(asm)
                asmlen = varint_bytesize(int(len(asm) // 2))
                self.unsignedtx = self.unsignedtx + str(asmlen) + asm
        self.unsignedtx = self.unsignedtx + self.nlocktime
        self.unsignedtx = str(self.unsignedtx)

    def add_multisig_amount_to_sigs_len(self,redeemscript):
        try:
            m_num_keys, y = SimpleBitcoinTx.validate_redeem_script_and_return_keys(redeemscript)
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
        sighashall_thisinput_tx = str(self.versionhex) + str(varint_bytesize(len(self.inputs)))
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
        sighashall_thisinput_tx = sighashall_thisinput_tx + str(varint_bytesize(len(self.outputs)))
        for i in range(len(self.outputs)):
            if self.outputs[i][0] == "OP_RETURN":
                lenopreturndata = str(varint_bytesize(int(len(self.outputs[i][1]) // 2)))
                outputstr = str("6a") + lenopreturndata + str(self.outputs[i][1]) # OP_RETURN + size of data + data
                totaloutputlen = str(varint_bytesize(int(len(outputstr) // 2)))
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
                    asm = str("a9") + str(varint_bytesize(int(len(outputhex[2:]) // 2))) + str(outputhex[2:]) + str("87") # OP_HASH160 .... OP_EQUAL
                elif outputhex[:2] == "00":
                    asm = str("76a9") + str(varint_bytesize(int(len(outputhex[2:]) // 2))) + str(outputhex[2:]) + str("88ac") # OP_DUP OP_HASH160 .... OP_EQUALVERIFY OP_CHECKSIG
                else:
                    sighashall_thisinput_tx = str("")
                    raise Exception("Output " + str(i) + " is not a recognized address. Only 1BitcoinAddress and 3PaytoScriptHash address formats are valid. This class is called 'SimpleBitcoinTx' for a reason!")
                asm = str(asm)
                asmlen = varint_bytesize(int(len(asm) // 2))
                sighashall_thisinput_tx = sighashall_thisinput_tx + str(asmlen) + asm
        sighashall_thisinput_tx = sighashall_thisinput_tx + self.nlocktime # Add lock time
        sighashall_thisinput_tx = sighashall_thisinput_tx + str("01000000") # add SIGHASH_ALL to end
        sighashall_thisinput_tx = str(sighashall_thisinput_tx)
        txhash = double_sha256(sighashall_thisinput_tx)
        newsig, compressedpubkey = sign_hash(txhash,privkey,str("RFC6979_SHA256"),True)
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
        sighashall_thisinput_tx = str(self.versionhex) + str(varint_bytesize(len(self.inputs)))
        for i in range(len(self.inputs)):
            sighashall_thisinput_tx = sighashall_thisinput_tx + str(reverse_bytes(self.inputs[i][0]))
            assert len(str(reverse_bytes(hexlify_(int(self.inputs[i][1]),8)))) == 8
            sighashall_thisinput_tx = sighashall_thisinput_tx + str(reverse_bytes(hexlify_(int(self.inputs[i][1]),8)))
            if i != tx_input_num:
                sighashall_thisinput_tx = sighashall_thisinput_tx + str("00")
            else:
                redeemscript_len = str(varint_bytesize(int(len(self.inputs[tx_input_num][3]) // 2)))
                sighashall_thisinput_tx = sighashall_thisinput_tx + str(redeemscript_len) + str(self.inputs[tx_input_num][3])
            assert len(str(reverse_bytes(hexlify_(int(self.inputs[i][4]),8)))) == 8
            sighashall_thisinput_tx = sighashall_thisinput_tx + str(reverse_bytes(hexlify_(int(self.inputs[i][4]),8)))
        sighashall_thisinput_tx = sighashall_thisinput_tx + str(varint_bytesize(len(self.outputs)))
        for i in range(len(self.outputs)):
            if self.outputs[i][0] == "OP_RETURN":
                lenopreturndata = str(varint_bytesize(int(len(self.outputs[i][1]) // 2)))
                outputstr = str("6a") + lenopreturndata + str(self.outputs[i][1]) # OP_RETURN + size of data + data
                totaloutputlen = str(varint_bytesize(int(len(outputstr) // 2)))
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
                    asm = str("a9") + str(varint_bytesize(int(len(outputhex[2:]) // 2))) + str(outputhex[2:]) + str("87") # OP_HASH160 .... OP_EQUAL
                elif outputhex[:2] == "00":
                    asm = str("76a9") + str(varint_bytesize(int(len(outputhex[2:]) // 2))) + str(outputhex[2:]) + str("88ac") # OP_DUP OP_HASH160 .... OP_EQUALVERIFY OP_CHECKSIG
                else:
                    sighashall_thisinput_tx = str("")
                    raise Exception("Output " + str(i) + " is not a recognized address. Only 1BitcoinAddress and 3PaytoScriptHash address formats are valid. This class is called 'SimpleBitcoinTx' for a reason!")
                asm = str(asm)
                asmlen = varint_bytesize(int(len(asm) // 2))
                sighashall_thisinput_tx = sighashall_thisinput_tx + str(asmlen) + asm
        sighashall_thisinput_tx = sighashall_thisinput_tx + self.nlocktime # Add lock time
        sighashall_thisinput_tx = sighashall_thisinput_tx + str("01000000") # add SIGHASH_ALL to end
        sighashall_thisinput_tx = str(sighashall_thisinput_tx)
        txhash = double_sha256(sighashall_thisinput_tx)
        newsig, compressedpubkey = sign_hash(txhash,privkey,str("RFC6979_SHA256"),True)
        uncompressedpubkey = uncompress_pubkey(compressedpubkey)
        newsig = str(newsig + str("01")) # add SIGHASH_ALL to end of sig
        try:
            num_sigs_req, pubkeylist = SimpleBitcoinTx.validate_redeem_script_and_return_keys(self.inputs[tx_input_num][3])
        except:
            raise Exception("Error validating redeem script for input that is attempting to be signed.")
        if compressedpubkey in pubkeylist:
            self.sigs[tx_input_num].append(str(newsig))
            # if self.sigs[tx_input_num][0] == "":
                # del self.sigs[tx_input_num][0]
            self.sigspubkeylist[tx_input_num].append(str(compressedpubkey))
            # if self.sigspubkeylist[tx_input_num][0] == "":
                # del self.sigspubkeylist[tx_input_num][0]
            self.sort_multisig_input_sigs_and_keys_to_redeemscript_order(tx_input_num)
        elif uncompressedpubkey in pubkeylist:
            self.sigs[tx_input_num].append(str(newsig))
            # if self.sigs[tx_input_num][0] == "":
                # del self.sigs[tx_input_num][0]
            self.sigspubkeylist[tx_input_num].append(str(uncompressedpubkey))
            # if self.sigspubkeylist[tx_input_num][0] == "":
                # del self.sigspubkeylist[tx_input_num][0]
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
            x, sortedpubkeylist = SimpleBitcoinTx.validate_redeem_script_and_return_keys(redeemscript)
        except Exception as e:
            raise Exception(str(e))
        else:
            # if len(self.sigs[tx_input_num]) > x:
                # if self.sigs[tx_input_num][0] == "":
                    # del self.sigs[tx_input_num][0]
            # if len(self.sigspubkeylist[tx_input_num]) > x:
                # if self.sigspubkeylist[tx_input_num][0] == "":
                    # del self.sigspubkeylist[tx_input_num][0]
            if len(self.sigs[tx_input_num]) > x+1 or len(self.sigspubkeylist[tx_input_num]) > x+1:
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
        i = 0
        while i < listlen:
            del self.sigs[tx_input_num][0]
            del self.sigspubkeylist[tx_input_num][0]
            i = i+1
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
        if len(self.sigs[tx_input_num]) > x or len(self.sigspubkeylist[tx_input_num]) > x:
            raise Exception("Length of sig list or pubkey list greater than m for redeem script. (2)")
        x, sortedpubkeylist, newsortedsiglist, newsortedpubkeylist, unsorted_pubkeylist = None, None, None, None, None

    def update_tx_with_sigs(self):
        assert len(self.sigs) == len(self.sigspubkeylist)
        assert len(self.inputs) != 0
        assert len(self.outputs) != 0
        assert len(self.unsignedtx) != 0 and self.unsignedtx != ""
        self.partialtx = str(self.versionhex) + str(varint_bytesize(len(self.inputs)))
        for i in range(len(self.inputs)):
            self.partialtx = str(self.partialtx) + str(reverse_bytes(self.inputs[i][0])) + str(reverse_bytes(hexlify_(int(self.inputs[i][1]),8)))
            if self.inputs[i][2][:6] == "76a914" and len(self.inputs[i][2]) == 50:
                if self.sigs[i] == "":
                    self.partialtx = str(self.partialtx) + str("00")
                else:
                    siglen = varint_bytesize(int(len(self.sigs[i]) // 2))
                    pubkeylen = varint_bytesize(int(len(self.sigspubkeylist[i]) // 2))
                    inputstr = str(siglen) + str(self.sigs[i]) + str(pubkeylen) + str(self.sigspubkeylist[i])
                    inputstrlen = varint_bytesize(int(len(inputstr) // 2))
                    self.partialtx = str(self.partialtx) + str(inputstrlen) + str(inputstr)
            elif self.inputs[i][2][:4] == "a914" and len(self.inputs[i][2]) == 46:
                #add 00 for extra checkmultisigverify byte
                sigs_and_redeemscript = str("")
                hasonesig = False
                for j in range(len(self.sigs[i])):
                    if self.sigs[i][j] == "":
                        continue
                    hasonesig = True
                    siglen = varint_bytesize(int(len(str(self.sigs[i][j])) // 2))
                    sigs_and_redeemscript = str(sigs_and_redeemscript) + str(siglen) + str(self.sigs[i][j])
                if not hasonesig:
                    self.partialtx = str(self.partialtx) + str("00")
                else:
                    assert self.inputs[i][3] != ""
                    rs_len = varint_bytesize(int(len(str(self.inputs[i][3])) // 2))
                    sigs_and_redeemscript = str(sigs_and_redeemscript) + str("4c") + str(rs_len) + str(self.inputs[i][3])
                    sigs_and_redeemscript = str("00") + str(sigs_and_redeemscript) # for bug where OP_CHECKMULTISIG drops an extra byte
                    srs_len = varint_bytesize(int(len(str(sigs_and_redeemscript)) // 2))
                    self.partialtx = str(self.partialtx) + str(srs_len) + str(sigs_and_redeemscript)
            else:
                raise Exception("Error with inputs.")
            sequencebytes = hexlify_(self.inputs[i][4],8)
            assert len(sequencebytes) == 8
            sequencebytes = reverse_bytes(sequencebytes)
            self.partialtx = str(self.partialtx) + str(sequencebytes)
        self.partialtx = str(self.partialtx) + str(varint_bytesize(int(len(self.outputs))))
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
                outhex_len = str(varint_bytesize(int(len(outhex) // 2)))
                assert outhex_len == "14"
                asm_len = str(varint_bytesize(int(len(str(str("76a9") + str(outhex_len) + str(outhex) + str("88ac"))) // 2)))
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
                outhex_len = str(varint_bytesize(int(len(outhex) // 2)))
                assert outhex_len == "14"
                asm_len = str(varint_bytesize(int(len(str(str("a9") + str(outhex_len) + str(outhex) + str("87"))) // 2)))
                assert asm_len == "17"
                self.partialtx = str(self.partialtx) + str(asm_len) + str("a9") + str(outhex_len) + str(outhex) + str("87")
            elif self.outputs[i][0] == "OP_RETURN":
                self.partialtx = str(self.partialtx) + str("0000000000000000")
                opreturnhex = str(self.outputs[i][1])
                try:
                    opreturnhex = hexlify_(binascii.unhexlify(opreturnhex))
                except:
                    raise Exception("Unknown error with OP_RETURN data on input " + str(i))
                opreturnlen1 = str(varint_bytesize(int(len(opreturnhex) // 2)))
                opreturn = str("6a") + str(opreturnlen) + str(opreturnhex)
                opreturnlen2 = str(varint_bytesize(int(len(opreturn) // 2)))
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
            amount = round(float(round(float(int(reverse_bytes(remainingtx[:16]),16)),8) / 100000000.0),8)
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
            reconstructedtx = reconstructedtx + varint_bytesize(num_inputs)
            for j in range(len(self.inputs)):
                reconstructedtx = reconstructedtx + reverse_bytes(self.inputs[j][0])
                reconstructedtx = reconstructedtx + reverse_bytes(hexlify_(self.inputs[j][1],8))
                if self.inputs[j][2][:4] == "a914" and i == num_multisig_inputs_checked_so_far:
                    assert len(self.inputs[j][3]) != 0
                    rs_len = varint_bytesize(int(len(self.inputs[j][3]) / 2))
                    reconstructedtx = reconstructedtx + rs_len + str(self.inputs[j][3])
                else:
                    reconstructedtx = reconstructedtx + str("00")
                reconstructedtx = reconstructedtx + reverse_bytes(hexlify_(int(self.inputs[j][4]),8))
            reconstructedtx = reconstructedtx + varint_bytesize(num_outputs)
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
                    opreturn_len = str(varint_bytesize(int(len(new_asm) / 2)))
                    new_asm = str("6a") + opreturn_len + new_asm
                else:
                    raise Exception("Problem with output number " + str(j) + " in imported tx while verifying multisig keys.")
                new_asm_len = str(varint_bytesize(int(len(new_asm) / 2)))
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
