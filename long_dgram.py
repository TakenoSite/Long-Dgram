import struct 
import random, string 
import socket 

class UTIL:
    def __init__(self):
        pass 

    def random_id(self, s_len:int)->str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=s_len))


class LOGN_UDP_PACKET:
    def __init__(self, packet_size:int):
        self.util = UTIL()
        self.packet_size = packet_size

        self.sequence_id_l = 7
        self.sequence_format = "!Ix"+str(self.sequence_id_l)+"sx"

        self.packet_index = {}
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
            packet_with_sequence = struct.pack(self.sequence_format, sequence_number, sequence_id) + data
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



class FROM_UDP_SOCKET:
    def __init__(self, addr: list, packet_size=1024):
        self.addr = addr
        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        self.packet_size = packet_size
        self.long_udp = LOGN_UDP_PACKET(packet_size)
        pass

    def udp_sock(self):
        return self.sockfd

    def udp_sockclose(self):
        self.sockfd.close()
        return

    def udp_socktimeout(self, t: int):
        self.sockfd.settimeout(t)
        return

    def udp_sender(self, payload:bytes):
        self.sockfd.sendto(payload, self.addr)
        return

    def udp_bind(self):
        self.sockfd.bind(self.addr)
        return

    def udp_recv(self, bufsize:int) -> list:
        data, addr = self.sockfd.recvfrom(bufsize)
        return data, addr
    
    def logn_udp_sendto(self, payloads:bytes):
        if type(payloads) !=  bytes:
            print("Data type of payload is not bytes.")
            return None
         
        for packets in self.long_udp.packet_encode(payloads):
            print(packets)
            self.udp_sender(packets)
        return
    
    def long_udp_recv(self)->bytes:
        while True:
            data,addr = self.udp_recv(self.packet_size+128)
            status = self.long_udp.packet_rebuild(data)
            if status != None:
                return status,addr



# end
