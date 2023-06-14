import struct
import string 
import random
import socket 
import time 
import sys
import base64

from util import UTIL
from long_udp_packet import LOGN_UDP_PACKET
from socket_util import RTO, checksum, udp_checksum_with_payload
from crypto import CRYPT


class FROM_UDP_SOCKET: 
    def __init__(self, addr: list, packet_size=1024, rsa_keys_lenght=2048):
        
        self.addr = addr
        self.sockdg = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
         
        self.packet_size = packet_size
        self.long_udp = LOGN_UDP_PACKET(packet_size)
        
        self.crypt = CRYPT(rsa_keys_lenght)
        self.keyinfo = {"priv_key":None, "pub_key":None}

        pass

    def udp_socketname(self):
        return self.sockdg

    def udp_sockclose(self):
        self.sockdg.close()
        return

    def udp_socktimeout(self, t: int):
        self.sockdg.settimeout(t)
        return

    def udp_sendto(self, payload:bytes):
        self.sockdg.sendto(payload, self.addr)
        return

    def udp_bind(self):
        self.sockdg.bind(self.addr)
        return

    def udp_recv(self, bufsize:int) -> list:
        data, addr = self.sockdg.recvfrom(bufsize)
        return data, addr
    

    def udp_secure_sendto(self, payloads:bytes): 
        if self.keyinfo["pub_key"] == None:
            self.udp_sendto(self.crypt.key_transmission_code)
            self.udp_socktimeout(1)
            
            try:
                data, _ = self.udp_recv(1024)
            except:
                return -1
            
            rsa_public_key_decode = base64.b64decode(data)
            rsa_public_key_unpack = struct.unpack("={}sxQx".format(self.crypt.rsa_keys_lenght_to_bytes), 
                    rsa_public_key_decode)
            
            rsa_public_keys = self.crypt.rsa.util.bytes_to_long(rsa_public_key_unpack[0])
            self.keyinfo = {"pub_key":{"max":rsa_public_keys, "e":rsa_public_key_unpack[1]}, "priv_key":None}


        encrypted = self.crypt.rsa.util.long_to_bytes(self.crypt.rsa.rsa_encrypt(payloads, pub_key=self.keyinfo["pub_key"])[0])
        if encrypted == None:
            return -2
        
        
        encrypt_payload = self.crypt.rsa_encrypt_msg_code + encrypted
        self.udp_sendto(encrypt_payload)
        
        return 0
    
     
    def udp_secure_recv(self, bufsize:int)->list:
        if self.keyinfo["priv_key"] == None: # gen rsa_key
            print("gen_keys..")
            gen_keys = self.crypt.rsa_generate_keys()
        
            key_encode = self.crypt.rsa.rsa_encode_keys(gen_keys) 
            pub_key  = key_encode[0][0]
            priv_key = key_encode[0][1]
            self.keyinfo = {
                    "pub_key":pub_key, 
                    "priv_key":gen_keys["priv"]
                    }
            print("complete")
             
        # key transmission 
        secure_recv_bufsize = (self.crypt.rsa_keys_lenght // 8) + 0xf 
        while 1:
            data,addr = self.udp_recv(secure_recv_bufsize)
            #print(data)
            if data == self.crypt.key_transmission_code: # key transmission 
                self.sockdg.sendto(self.keyinfo["pub_key"], addr) 
                    
            elif data[:4] == self.crypt.rsa_encrypt_msg_code: # decrypted
                # Decryption by private key
                decrypted = self.crypt.rsa.rsa_decrypt([self.crypt.rsa.util.bytes_to_long(data[4:])], 
                        self.keyinfo["priv_key"])
                
                #decrypted = data

                return decrypted, addr 

    
    
    def long_udp_sendto(self, payloads:bytes, set_error_limit=10):
        if type(payloads) !=  bytes:
            print("Data type of payload is not bytes.")
            return None
        
        rto_func = RTO() 
         
        for packets in self.long_udp.packet_encode(payloads):
            error_count = 0
             
            while 1:
                start_t = time.time()
                rto = rto_func.resolve_rto() # RTO算出
                self.udp_socktimeout(rto)
                
                # チェックサムを入れる
                packet_with_checksum = udp_checksum_with_payload(src_ip="0.0.0.0",  
                        dst_ip=self.addr[0],payloads=packets) 
                
                # print(packet_with_checksum) # debug 
                self.udp_sendto(packet_with_checksum)
                
                try:
                    self.udp_recv(0xf) #ack受信
                except:
                    error_count += 1
                    if error_count == set_error_limit:
                        # timeout 
                        return -1
                    continue

                end_t = time.time()
                response_t = round((end_t-start_t), 4) #tt算出
                rto_func.resolve_srtt(response_t) # SRTT算出
                break 
        return 0
    
    
    def long_udp_recv(self)->bytes:
        ack = struct.pack("!3s", b"ack")

        while True:
            packet,addr = self.udp_recv(self.packet_size+128)
            
            try:
                checksum_value = struct.unpack("!Hx", packet[:3])[0]
            except:
                continue

            rhost = addr[0]
            lhost = "0.0.0.0" #擬似shost  

            payload = packet[3:]
            payload_l =  11 + len(payload) 

            dgram_pseudoheder = struct.pack("!4s4sBBH", socket.inet_aton(lhost), 
                    socket.inet_aton(rhost), 0, 17, payload_l) #擬似ヘッダー
             
            dgram_pseudopacket = dgram_pseudoheder + payload 
            checksum_calculated = checksum(dgram_pseudopacket) #checksum 算出

            # 整合性を確認
            if checksum_value == checksum_calculated:
                data = self.long_udp.packet_rebuild(payload)
                self.sockdg.sendto(ack, addr) # ack
                if data != None:
                    #print(data[:20], len(data)) debug 
                    return data,addr

                
# end
