import sys
import struct

sys.path.append("./rsa") 
from rsa_models import RSA


class CRYPT:
    def __init__(self, rsa_keys_lenght:int):
        self.rsa_keys_lenght = rsa_keys_lenght
        self.rsa_keys_lenght_to_bytes = rsa_keys_lenght // 8

        self.rsa = RSA(rsa_keys_lenght)
        self.key_transmission_code = struct.pack("!7s",b"key_req")
        self.rsa_encrypt_msg_code = struct.pack("!3sx",b"rsa")

        pass 

    def rsa_generate_keys(self):
        return self.rsa.rsa_generate_keys(self.rsa_keys_lenght)
 
