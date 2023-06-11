from rsa_util import UTIL
from rsa_math import MATH

import struct 
import base64

class RSA:
    def __init__(self, keys_len:int):
        self.math = MATH()
        self.util = UTIL()

        self.keys_len = keys_len // 8

    def padding(self, payloads:bytes, key_len:int):
        hash_value = self.util.hash_sha2(payloads) # sha256 
        
        rand_str = struct.pack("!4s", 
                bytes(self.util.random_string(4), encoding="utf-8")) 
        
        padding_length = key_len - len(payloads) - len(hash_value) - 6
        if padding_length < 0:
            raise ValueError("Plaintext is too long.")
        
        padding = b'\x00' * (padding_length - 4)
        padded_message = b'\x00' + hash_value + rand_str + padding + b'\x01' + payloads 
        c = self.util.bytes_to_long(padded_message)
        
        return c

    def rsa_encode_keys(self, gen_key:dict)->list:
        pub_key = gen_key["pub"]
        priv_key = gen_key["priv"]
        exponent = pub_key["e"]

        prime_1 = gen_key["prime1"]
        prime_2 = gen_key["prime2"]
        
        
        pubkey_hex = self.util.long_to_bytes(pub_key["max"])
        privekey_hex = self.util.long_to_bytes(priv_key["e"])
        prime_1_bytes = self.util.long_to_bytes(prime_1)
        prime_2_bytes = self.util.long_to_bytes(prime_2)
        
        pubkey_l = len(pubkey_hex)
        prime_l  = len(prime_1_bytes)
        

        pub_format  = "={}sxQx".format(pubkey_l)
        priv_format = "={}sx{}sx{}sx{}s".format(pubkey_l, pubkey_l, prime_l, prime_l)
        
        pub_info    = struct.pack(pub_format, pubkey_hex, exponent)
        priv_info   = struct.pack(priv_format, pubkey_hex, privekey_hex, prime_1_bytes, prime_2_bytes)
        
        pubkey_encode   = base64.b64encode(pub_info)
        privkeys_encode = base64.b64encode(priv_info)
        
        return [[pubkey_encode, privkeys_encode],[pub_format, priv_format]]
    
    #def rsa_decode_keys(self,s keyinfo:dict)->dict:
        


    
    def rsa_load_keys(self, public_key_file:str, private_key_file:str, key_length=1024)->dict:
        keys = {"pub":{"max":0, "e":0}, 
                "priv":{"max":0, "e":0},
                "prime1":0,
                "prime2":0 }

        
        key_bytes_l  = key_length // 8
        to_half_l    = key_bytes_l // 2

        key_format = {
                "pub":"={}sxQx".format(key_bytes_l),
                "priv":"{}sx{}sx{}sx{}s".format(key_bytes_l, key_bytes_l, to_half_l, to_half_l)
                }

        pub_key_file = open(public_key_file, "r")
        priv_key_file = open(private_key_file, "r")

        for pub, priv in zip(pub_key_file, priv_key_file):
            

            pub_key_decode  = base64.b64decode(pub.encode())
            priv_key_decode = base64.b64decode(priv.encode())
            
            pub_key_unpack  = struct.unpack(key_format["pub"], pub_key_decode)
            priv_key_unpack = struct.unpack(key_format["priv"], priv_key_decode)
            

            keys["pub"]     = {"max":self.util.bytes_to_long(pub_key_unpack[0]), "e":pub_key_unpack[1]}
            keys["priv"]    = {"max":self.util.bytes_to_long(priv_key_unpack[0]),
                    "e":self.util.bytes_to_long(priv_key_unpack[1])}
            
            keys["prime1"]  = self.util.bytes_to_long(priv_key_unpack[2])
            keys["prime2"]  = self.util.bytes_to_long(priv_key_unpack[3])
            
        return keys
    
    

    def rsa_generate_keys(self, bit_size:int)->dict:
        keys = {"pub":{"max":0, "e":0}, 
                "priv":{"max":0, "e":0},
                "prime1":0,
                "prime2":0 }
        
        p = 0
        q = 0
        
        e = (2 << 15) + 1  # 範囲設定 
        d = 0
        
        max_n = 0
        max_phi = 0
        
        if bit_size < 1024:
            raise ValueError("Select 1024bit or more")

        while not (p and q) or (p == q) or (self.math.gcd(max_phi, e) != 1):
            
            size_prime = bit_size // 2
            gen_prime = self.math.generate_prime(2, size_prime)
            
            p = gen_prime[0]
            q = gen_prime[1]

            max_n = p*q
            max_phi = (p - 1)*(q - 1)
             

        d = self.math.ext_euclid(max_phi, e)
        while d < 0:
            d = d + max_phi
        
        keys["pub"]     = {"max":max_n, "e":e}
        keys["priv"]    = {"max":max_n, "e":d}
        keys["prime1"]  = p
        keys["prime2"]  = q

        return keys
    

    def rsa_encrypt(self, msg:bytes, pub_key:dict)->list:
        encrypted = []
        pd = [self.padding(msg, self.keys_len)]
        for s in pd:
            
            encry = self.math.modular_exp(s, pub_key["e"], pub_key["max"])
            if encry == -1:
                return None

            encrypted.append(encry)
       
        return encrypted


    def rsa_decrypt(self, msg:list, priv_key:dict)->list:
        decrypted = []
        for s in msg:
            decrypt = self.math.modular_exp(s, priv_key["e"] , priv_key["max"])
            if decrypt == -1:
                return None
             
            dbytes = self.util.long_to_bytes(decrypt)
            
            dhash = dbytes[:32].hex()
            dpayload = dbytes[36:]
    
            start_index = dpayload.split(b"\x01")
            if len(start_index) == 0:
                return None
             
            mpayloads = start_index[1]
            phash = self.util.hash_sha2(mpayloads).hex()
            
            if phash != dhash:
                return None
            
            decrypted.append(mpayloads)

        return decrypted
    
    
    def certificate(self, doc:bytes, priv_key:dict)->dict:
        
        value = {
                "doc" : None,
                "certificate":None
                }
        
        to_long = self.util.bytes_to_long(doc)

        gen_proof = self.math.modular_exp(to_long, priv_key["e"], priv_key["max"])
        if gen_proof == -1:
            return None
        
        value["doc"] =  doc
        value["certificate"] = gen_proof

        return value
    
    
    def certificate_proof(self, c, pub_keys:dict):
        
        proof = self.math.modular_exp(c, pub_keys["e"], pub_keys["max"])
        if proof == -1:
            return None 

        return proof


#end
