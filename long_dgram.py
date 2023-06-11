import struct
import string 
import random
import socket 
import time 
import sys
import base64

sys.path.append("./rsa") 
from rsa_models import RSA


class UTIL:
    def __init__(self):
        pass 

    def random_id(self, s_len:int)->str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=s_len))


class LOGN_UDP_PACKET:
    def __init__(self, packet_size:int):
        self.util = UTIL()
        
        # udp packet maxsize : 65535  
        # udp header  : 8
        # udp payload max size : 65535 - 8
        self.packet_size = packet_size
        
        self.sequence_id_l = 7
        self.sequence_format = "!Ix"+str(self.sequence_id_l)+"sx"
        
        self.packet_index = {}
        
        if packet_size > (((2 << 15)-1) - (5+self.sequence_id_l)):
            ValueError("packet_size is too large")
            sys.exit(42) 
            
        pass 
    
    def packet_split(self, data):
        packet_list = []
        sequence_number = 2

        while data:
            packet = data[:self.packet_size]
            data = data[self.packet_size:]
            if data:
                packet_list.append((sequence_number, packet))
            else:
                if sequence_number == 2:
                    packet_list.append((1, packet)) # if no split 
                else:
                    packet_list.append((0, packet)) # if last split 
                break  
            sequence_number += 1
             
        return packet_list
        

    def packet_encode(self, payloads:bytes)->list:
        sequence_id = bytes(self.util.random_id(self.sequence_id_l), encoding="utf-8")
        split_packet_list = []
        payloads = self.packet_split(payloads)

        for sequence_number, data in payloads:
            packet_with_sequence = struct.pack(self.sequence_format,
                    sequence_number, sequence_id) + data
            
            split_packet_list.append(packet_with_sequence)
        return split_packet_list
    
    
    def packet_decode(self, raw_packet:bytes):
        header_l = 6 + self.sequence_id_l
        try:
            return struct.unpack(self.sequence_format, raw_packet[:header_l]), raw_packet[header_l:]
        except:
            return None


    def packet_rebuild(self, raw_packet:bytes):
        packet_info = self.packet_decode(raw_packet)
        if packet_info == None:
            return None

        sequence_number = packet_info[0][0]
        sequence_id     = packet_info[0][1]
        
        if sequence_number == 1: # no split
            return packet_info[1]
            
        elif sequence_number == 2 : #fist sequence
            self.packet_index[sequence_id] = {sequence_number:packet_info[1]}
        
        elif sequence_number == 0: #last sequence
            try:
                max_sequence_number = list(self.packet_index[sequence_id].keys())[-1]
            except:
                return None
            self.packet_index[sequence_id].update({max_sequence_number+1:packet_info[1]})
            split_packet_sort_list = sorted(self.packet_index[sequence_id].items())
            
            add_packets = []
            sequence_number = 2
            for expected_sequence_number, payloads in split_packet_sort_list:
                if sequence_number == expected_sequence_number:
                    add_packets.append(payloads)
                    packet_build = b"".join(add_packets)
                     
                else:
                    # loss packets
                    self.packet_index.pop(sequence_id)
                    return None
                
                sequence_number +=1
            self.packet_index.pop(sequence_id)
            return packet_build  # complete packets
            # noen response ark  
        else:
            try:
                self.packet_index[sequence_id].update({sequence_number:packet_info[1]})
            except:
                pass 
            return None




"""
  acknowledgment it advances SND.UNA.  The extent to which the values of
  these variables differ is a measure of the delay in the communication.
  The amount by which the variables are advanced is the length of the
  data in the segment.  Note that once in the ESTABLISHED state all
  segments must carry current acknowledgment information.

  The CLOSE user call implies a push function, as does the FIN control
  flag in an incoming segment.

  Retransmission Timeout

  Because of the variability of the networks that compose an
  internetwork system and the wide range of uses of TCP connections the
  retransmission timeout must be dynamically determined.  One procedure
  for determining a retransmission time out is given here as an
  illustration.

    An Example Retransmission Timeout Procedure

      Measure the elapsed time between sending a data octet with a
      particular sequence number and receiving an acknowledgment that
      covers that sequence number (segments sent do not have to match
      segments received).  This measured elapsed time is the Round Trip
      Time (RTT).  Next compute a Smoothed Round Trip Time (SRTT) as:

        SRTT = ( ALPHA * SRTT ) + ((1-ALPHA) * RTT) 

      and based on this, compute the retransmission timeout (RTO) as:

        RTO = min[UBOUND,max[LBOUND,(BETA*SRTT)]]

      where UBOUND is an upper bound on the timeout (e.g., 1 minute),
      LBOUND is a lower bound on the timeout (e.g., 1 second), ALPHA is
      a smoothing factor (e.g., .8 to .9), and BETA is a delay variance
      factor (e.g., 1.3 to 2.0).

  The Communication of Urgent Information

  The objective of the TCP urgent mechanism is to allow the sending user
  to stimulate the receiving user to accept some urgent data and to
  permit the receiving TCP to indicate to the receiving user when all
  the currently known urgent data has been received by the user.

  This mechanism permits a point in the data stream to be designated as
  the end of urgent information.  Whenever this point is in advance of
  the receive sequence number (RCV.NXT) at the receiving TCP, that TCP
  must tell the user to go into "urgent mode"; when the receive sequence
  number catches up to the urgent pointer, the TCP must tell user to go
"""

class RTO:
    def __init__(self):
        self.rto = 0
        self.alpha = 0.8
        self.beta = 2.0
        self.ubound = 10
        self.lbound = 1.0e-04
    
        self.rtt = []
        self.rtt_len = 0
        self.srtt = [0.1, 0.1]

    def resolve_srtt(self, t:float)->float:
        self.rtt.append(t)
        self.rtt_len = len(self.rtt)
        
        if self.rtt_len < 2:
            return  
        
        self.srtt.append(self.alpha * self.srtt[-2] + ((1 - self.alpha) * self.rtt[-1]))

        if self.rtt_len > 100: #  
            del self.rtt[0]

    def resolve_rto(self)->float:
        
        if self.rtt_len < 2:
            rto = 1
            return rto

        rto = min(self.ubound, max(self.lbound, self.beta*self.srtt[-1]))
        return rto




"""
    Checksum:  16 bits
    The checksum field is the 16 bit one's complement of the one's
    complement sum of all 16 bit words in the header and text.  If a
    segment contains an odd number of header and text octets to be
    checksummed, the last octet is padded on the right with zeros to
    form a 16 bit word for checksum purposes.  The pad is not
    transmitted as part of the segment.  While computing the checksum,
    the checksum field itself is replaced with zeros.

    The checksum also covers a 96 bit pseudo header conceptually
"""

def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'

    n = 0
    for i in range(0, len(data), 2):
        word = struct.unpack("!H", data[i:i+2])[0]
        n += word
    
    resolve = (n >> 16) + (n & 0xffff)
    resolve += resolve
    
    resolve = ~resolve & 0xffff
    resolve -= 1
    
    return resolve


def udp_checksum_with_payload(src_ip:str, dst_ip:str, payloads:bytes) -> bytes:
    
    udp_length = 11 + len(payloads)  # UDPヘッダとペイロードの長さ
   
    udp_pseudoheader  = struct.pack('!4s4sBBH', socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip), 0, 17, udp_length) # 擬似ヘッダーを作成
    
    udp_packet = udp_pseudoheader + payloads # パケットを作成

    checksum_calculated = checksum(udp_packet) # チェックサムを計算
    
    #print(checksum_n) debug 

    # チェックサム値をペイロードに仕込む
    checksums_with_payloads = struct.pack("!Hx", checksum_calculated) + payloads 
    return checksums_with_payloads


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
                data, _ = self.udp_recv(self.crypt.rsa_keys_lenght_to_bytes + 0xf)
            except:
                return -1
            
            rsa_public_key_decode = data
            rsa_public_key_unpack = struct.unpack("!{}sxQx".format(self.crypt.rsa_keys_lenght_to_bytes), rsa_public_key_decode)
            
            rsa_public_keys = self.crypt.rsa.util.bytes_to_long(rsa_public_key_unpack[0])
            self.keyinfo = {"pub_key":{"max":rsa_public_keys, "e":rsa_public_key_unpack[1]}, "priv_key":None}
        
         
        encrypted = self.crypt.rsa.util.long_to_bytes(self.crypt.rsa.rsa_encrypt(payloads, pub_key=self.keyinfo["pub_key"])[0])
        if encrypted == None:
            return -2
        
        
        encrypt_payload = self.crypt.rsa_encrypt_msg_code + encrypted
        self.udp_sendto(encrypt_payload)
    
    
    
    def udp_secure_recv(self, bufsize:int)->list:
        if self.keyinfo["priv_key"] == None: # gen rsa_key
            print("key gen ...")
            gen_keys = self.crypt.rsa_generate_keys()
        
            key_encode = self.crypt.rsa.rsa_encode_keys(gen_keys) 
            pub_key  = key_encode[0][0]
            priv_key = key_encode[0][1]
            self.keyinfo = {
                    "pub_encode_key":pub_key, 
                    "priv_encode_key":priv_key
                    }
            
            print("complete")
        # key transmission 
        
        secure_recv_bufsize = (self.crypt.rsa_keys_lenght // 8) + 0xf 
        self.udp_bind() 
        while 1:
            data,addr = self.udp_recv(secure_recv_bufsize)
            print(data)
            if data == self.crypt.key_transmission_code: # key transmission 
                
                #debug 
                r = base64.b64decode(self.keyinfo["pub_encode_key"]) # なぜか受信先でdecode できないため
                
                self.sockdg.sendto(r, addr) 
                    
            elif data[:4] == self.crypt.rsa_encrypt_msg_code: # decrypted
                print(gen_keys["priv"])
                decrypted = self.crypt.rsa.rsa_decrypt([self.crypt.rsa.util.bytes_to_long(data[4:])], gen_keys["priv"])
                print(decrypted) 
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
        return
    
    
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
