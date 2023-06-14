import struct 
import socket


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

