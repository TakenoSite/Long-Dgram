import struct 
import socket

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

        if self.rtt_len > 100: 
            del self.rtt[0]

    def resolve_rto(self)->float:
        
        if self.rtt_len < 2:
            rto = 1
            return rto

        rto = min(self.ubound, max(self.lbound, self.beta*self.srtt[-1]))
        return rto



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
    
    # 擬似ヘッダーを作成
    udp_pseudoheader  = struct.pack('!4s4sBBH', socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip), 0, 17, udp_length)
    # パケットを作成
    udp_packet = udp_pseudoheader + payloads
    # チェックサムを計算
    checksum_calculated = checksum(udp_packet)
    
    #print(checksum_n) debug 

    # チェックサム値をペイロードに仕込む
    checksums_with_payloads = struct.pack("!Hx", checksum_calculated) + payloads
     
    return checksums_with_payloads


