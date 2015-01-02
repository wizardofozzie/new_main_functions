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
# from ElectrumV2Seed import * # Not bug-checked yet, do not use!!!
# from DER_sign_and_verify import *
# from SimpleBitcoinTx import * # Not bug-checked yet, do not use!!!
# from msg_sign_and_verify import *
# from openassets import *

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
from .ElectrumV2Seed import * # Not bug-checked yet, do not use!!!
from .DER_sign_and_verify import *
from .SimpleBitcoinTx import * # Not bug-checked yet, do not use!!!
from .msg_sign_and_verify import *
from .openassets import *

# TODO:  Write doctests for SimpleBitcoinTx, check for bugs, fix bugs. Make sure doctests cover all use cases.

# TODO:  Doctest sha512 in hash_funcs and all of Electrum V2

# TODO:  Write extensive unittests for this entire module.

if __name__ == "__main__":
    import doctest
    doctest.testmod()
