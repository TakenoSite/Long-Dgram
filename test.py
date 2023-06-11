from long_dgram import FROM_UDP_SOCKET
import sys

arg = sys.argv


class TEST:
    def __init__(self, addr, packet_s:int):
        self.socket = FROM_UDP_SOCKET(addr=addr, packet_size=packet_s)
    

    def send(self, payload_s:int):
        payload = b"a" * payload_s
        self.socket.long_udp_sendto(payload)
    
    def recv(self):
        self.socket.udp_bind()
        data,addr = self.socket.long_udp_recv()
         
        print(data[:1], len(data),addr)

    def s_send(self,payload_s:int):
        p = b"a" * payload_s
        self.socket.udp_sendto(p)

    def s_recv(self):
        self.socket.udp_bind()
        
        while 1:
            data,addr = self.socket.long_udp_recv(512)
            print(data)
    
    def secure_recv(self):
        data,_ = self.socket.udp_secure_recv(1024)
        print(data)

    def secure_send(self, payload_length:int):
        p = b"b" * payload_length
        res = self.socket.udp_secure_sendto(p)
        print(res)
    
if __name__ == "__main__":
    
    addr = ("127.0.0.1", 1234)
    packet_split_size = 1024
    packet_payload_size = 3

    run = TEST(addr, packet_split_size)
     
    if arg[1] == "0":
        run.send(packet_payload_size)   

    elif arg[1] == "1":
        run.recv()
    
    elif arg[1] == "2":
        for i in range((2<<30) // 512):
            run. s_send(packet_payload_size)
    
    elif arg[1] == "3":
        run.s_recv()
        pass 
    
    elif arg[1] == "4":
        run.secure_recv() 
        pass 
    
    elif arg[1] == "5":
        run.secure_send(packet_payload_size)
        pass 
    
    
