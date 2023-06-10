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
         
        #print(data[:1], len(data),addr)


if __name__ == "__main__":
    
    addr = ("127.0.0.1", 1234)
    packet_split_size = 128
    packet_payload_size = 200000

    run = TEST(addr, packet_split_size)
     
    if arg[1] == "0":
        run.send(packet_payload_size)   

    elif arg[1] == "1":
        run.recv()

     
