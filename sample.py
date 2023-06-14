from dgram import FROM_UDP_SOCKET

# secure config 
rsa_key_langth = 2048

# long payload split size 
packet_size = 512

# set myaddr 
addr = ("127.0.0.1", 1234)

set_dgram = FROM_UDP_SOCKET(addr=addr, packet_size=packet_size, rsa_keys_lenght=rsa_key_langth)


