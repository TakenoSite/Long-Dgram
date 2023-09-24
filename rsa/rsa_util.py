# -*- coding: utf-8 -*-
#
#  Cipher/PKCS1_OAEP.py : PKCS#1 OAEP
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================


import struct 
import sys
import hashlib
import random
import string

class UTIL:
    def __init__(self):
        pass 

    def long_to_bytes(self, n:int, blocksize=0)->bytes:
        """Convert a positive integer to a byte string using big endian encoding.

        If :data:`blocksize` is absent or zero, the byte string will
        be of minimal length.

        Otherwise, the length of the byte string is guaranteed to be a multiple
        of :data:`blocksize`. If necessary, zeroes (``\\x00``) are added at the left.

        .. note::
            In Python 3, if you are sure that :data:`n` can fit into
            :data:`blocksize` bytes, you can simply use the native method instead::

                >>> n.to_bytes(blocksize, 'big')

            For instance::

                >>> n = 80
                >>> n.to_bytes(2, 'big')
                b'\\x00P'

            However, and unlike this ``long_to_bytes()`` function,
            an ``OverflowError`` exception is raised if :data:`n` does not fit.
        """

        if n < 0 or blocksize < 0:
            raise ValueError("Values must be non-negative")

        result = []
        pack = struct.pack

        # Fill the first block independently from the value of n
        bsr = blocksize
        while bsr >= 8:
            result.insert(0, pack('>Q', n & 0xFFFFFFFFFFFFFFFF))
            n = n >> 64
            bsr -= 8

        while bsr >= 4:
            result.insert(0, pack('>I', n & 0xFFFFFFFF))
            n = n >> 32
            bsr -= 4

        while bsr > 0:
            result.insert(0, pack('>B', n & 0xFF))
            n = n >> 8
            bsr -= 1

        if n == 0:
            if len(result) == 0:
                bresult = b'\x00'
            else:
                bresult = b''.join(result)
        else:
            # The encoded number exceeds the block size
            while n > 0:
                result.insert(0, pack('>Q', n & 0xFFFFFFFFFFFFFFFF))
                n = n >> 64
            result[0] = result[0].lstrip(b'\x00')
            bresult = b''.join(result)
            # bresult has minimum length here
            if blocksize > 0:
                target_len = ((len(bresult) - 1) // blocksize + 1) * blocksize
                bresult = b'\x00' * (target_len - len(bresult)) + bresult
        return bresult




    def bytes_to_long(self,s:bytes)->int:
        """Convert a byte string to a long integer (big endian).

        In Python 3.2+, use the native method instead::

            >>> int.from_bytes(s, 'big')

        For instance::

            >>> int.from_bytes(b'\x00P', 'big')
            80

        This is (essentially) the inverse of :func:`long_to_bytes`.
        """
        acc = 0

        unpack = struct.unpack

        # Up to Python 2.7.4, struct.unpack can't work with bytearrays nor
        # memoryviews
        if sys.version_info[0:3] < (2, 7, 4):
            if isinstance(s, bytearray):
                s = bytes(s)
            elif isinstance(s, memoryview):
                s = s.tobytes()

        length = len(s)
        if length % 4:
            extra = (4 - length % 4)
            s = b'\x00' * extra + s
            length = length + extra
        for i in range(0, length, 4):
            acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
        return acc


    def bytes_block_split(self, s:bytes, keys_len:int)->list:
                 
        split_data_list = []
        lhash = 18 # md5 + 2
        lmax = keys_len - lhash
        
        while s:
            packet = s[:lmax]
            s = s[lmax:]
            
            split_data_list.append(packet)
            
        return  split_data_list
    
    
    def hash_md5(self, s:bytes)->bytes:
        hash_func = hashlib.md5()
        hash_func.update(s)
        hash_value = hash_func.digest()

        return hash_value
    
    def hash_sha2(self, s:bytes)->bytes:
        hash_func = hashlib.sha256()
        hash_func.update(s)
        hash_value = hash_func.digest()

        return hash_value


    def long_len(self, i:int)->int:
        return len(list(str(i)))

    
    def random_string(self, s_len:int)->str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=s_len))
    
    
    def file_write(self, data:str, filename:str):
        f = open(filename, mode="w")
        f.write(str(data.decode()))
        f.close() 
        
        

# end
