import socket
import struct
import textwrap

'''
    Global variables for giving ceratin space.
'''

TAB_1 = '\t  - '
TAB_2 = '\t\t  - '
TAB_3 = '\t\t\t  - '
TAB_4 = '\t\t\t\t  - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

"""
    captures the incoming ethernet frames on the network intereface and prints the raw data 

    dest_mac  --->  destination mac addr  AA:BB:CC:DD:EE:FF
    src_mac   --->  source mac address    AA:BB:CC:DD:EE:FF
    eth_proto --->  ethernet protocol     ICMP,....
    
"""

def main():
    con = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(3))
    with open('Data.txt', 'w') as output_file:
        
        while True:
            raw_data , addr = con.recvfrom(65536)
            dest_mac, src_mac, eth_proto,data = ethernet_frame(raw_data)
            print('\n Ethernet Frame:')
            print(TAB_1 + '\nDestination: {}, Source: {}, Protocol: {}'.format(dest_mac ,src_mac , eth_proto))
            output_file.write('\n Ethernet Frame:')
            output_file.write('\n\t  - ' + ' Destination: {}, Source: {}, Protocol: {}'.format(dest_mac ,src_mac , eth_proto))


            if eth_proto == 8:
                (version, header_length , ttl, proto, src, traget, data) = ipv4_packet(data)
                print(TAB_1 + "ipv4 packet:")
                print(TAB_2 + "Version: {}, Header Length: {}, TTL: {}".format(version, header_length , ttl))
                print(TAB_2 + "Protocol: {}, Source: {}, Target: {}".format(proto, src, traget))
                output_file.write('\n\t  - ' + "ipv4 packet:")
                output_file.write('\n\t\t  - ' + "Version: {}, Header Length: {}, TTL: {}".format(version, header_length , ttl))
                output_file.write('\n\t\t  - ' + "Protocol: {}, Source: {}, Target: {}".format(proto, src, traget))
                # ICMP
                if proto == 1:
                    icmp_type, code, checksum , data = icmp_packet(data)
                    print(TAB_1 + "TCMP packet:")
                    print(TAB_2 + "Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                    print(TAB_2 + "DATA: ")
                    print(format_multi_line(DATA_TAB_3, data))
                    output_file.write('\n\t  - ' + "TCMP packet:")
                    output_file.write('\n\t\t  - ' + "Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                    output_file.write('\n\t\t  - ' + "DATA: \n")
                    output_file.write(format_multi_line('\t\t\t ', data))
                    
                # TCP
                elif proto == 6:
                    (src_port, dest_port, sequence , acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syc, flag_fin, data) = tcp_sag(data)
                    print(TAB_1 + 'TCP Segment:')
                    print(TAB_2 + 'Source Prot: {}, Destination Port: {}'.format(src_port,dest_port))
                    print(TAB_2 + 'Sequence: {}, Acknoledgement: {}'.format(sequence,acknowledgement))
                    print(TAB_2 + 'Flags:')
                    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syc, flag_fin))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, data))
                    output_file.write('\n\t  - ' + 'TCP Segment:')
                    output_file.write('\n\t\t  - ' + 'Source Prot: {}, Destination Port: {}'.format(src_port,dest_port))
                    output_file.write('\n\t\t  - ' + 'Sequence: {}, Acknoledgement: {}'.format(sequence,acknowledgement))
                    output_file.write('\n\t\t  - ' + 'Flags:')
                    output_file.write('\n\t\t\t  - ' + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syc, flag_fin))
                    output_file.write('\n\t\t  - ' + 'Data: \n')
                    output_file.write(format_multi_line('\t\t\t ', data))

                # UDP
                elif proto == 17:
                    src_port , dest_port, size, data = udp_seg(data)
                    print(TAB_1 + 'TCP Sagment')
                    print(TAB_2 + 'Source Prot: {}, Destination Port: {}, Length: {}'.format(src_port,dest_port,size))
                    output_file.write('\n\t  - ' + 'TCP Sagment')
                    output_file.write('\n\t\t  - ' + 'Source Prot: {}, Destination Port: {}, Length: {}'.format(src_port,dest_port,size))

                # other
                else:
                    print(TAB_1 + 'Data:')
                    print(format_multi_line(DATA_TAB_2, data))
                    output_file.write('\n\t  - ' + 'Data: \n')
                    output_file.write(format_multi_line('\t\t ', data))
            
            else:
                print('Data:')
                print(format_multi_line(DATA_TAB_1, data))
                output_file.write('Data: \n')
                output_file.write(format_multi_line('\t ', data))

            output_file.flush()  



"""
    unpacking the ethernet frame 
    6s ---->  6 refers to 6 bytes and s refers to String
    H  ---->  extract the next 2bytes as an unsigned integer
    data[:14]  -----> extracts the ethernet header 
    '!' ----> indicates that the data should be unpacke d usong network byte order.(small endian format)
"""

def ethernet_frame(data):
    dest_mac , src_mac , proto = struct.unpack('! 6s 6s H', data[:14])    #---> '!' indicates that the data should be unpacke d usong network byte order.
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto) , data[14:]

"""
    {:02x}.format ----> format the bytes into AA:BB:CC:DD:EE:FF format.
"""


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

"""
    Unpacking the ipv4 
    8x ----> 8 refers to 8byte and x referse to skip
    B -----> B refers to i byte
    4s ----> 4 refers to  4 byte and s refers to String
    data[:20] ----> Unpack order first 8 byte skiped + 2(1)B [ttl , proto] + 2 byte skiped + 2(4) [ src, traget ] = 20 bytes
"""

#  UNPACK ipv4 
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl , proto , src ,target = struct.unpack('!8x B B 2x 4s 4s' , data[:20] )
    return version,header_length ,ttl ,proto ,ipv4(src) ,ipv4(target),data[header_length:]



'''
    This function refurn the ipv4 address in the right order .
'''
def ipv4(addr):
    return '.'.join(map(str ,addr))

'''
    1 + 1 + 2 = 4
'''
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum , data[4:]

#  Unpack TCP

'''
    2 + 2 + 4 + 4 + 2 = 14
    [Offset (4 bits)][Reserved (6 bits)][U][A][P][R][S][F]
    offset_reserved_flags ---> 16 bits
    offset ----> bit shift by 12 and gets the  4 bit
    flag_urg ----> Performed AND by 32 and bit shift 5 to get 6th charact[U] from right
    flag_ack ----> performed AND by 16 and bit shifted by 4 to get 5th character [A] from right
    flag_psh ----> performed AND by 8 and bit shifted by 3 to get 4th character [P] from right
    flag_rst ----> performed AND by 4 and bit shifted by 2 to get 3rd character [R] from right
    flag_syc ----> performed AND by 2 and bit shifted by 1 to get 2nd  character [S] from right
    flag_fin ----> performed AND by 2 to get first character [F] from right
'''

def tcp_sag(data):
    (src_port, dest_port, sequence , acknowledgement, offset_resserved_flags) = struct.unpack('! H H L L H' ,data[:14])
    offeset = (offset_resserved_flags >> 12) * 4
    flag_urg = (offset_resserved_flags & 32) >> 5
    flag_ack = (offset_resserved_flags & 16) >> 4
    flag_psh = (offset_resserved_flags & 8) >> 3
    flag_rst = (offset_resserved_flags & 4) >> 2
    flag_syc = (offset_resserved_flags & 2) >> 1
    flag_fin = (offset_resserved_flags & 2)

    return src_port, dest_port, sequence , acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syc, flag_fin, data[offeset:]

'''
    UNPACK UDP SAGMENT
    2 + 2 + 2(1)[skipped] + 2 = 8
'''
# Unpack UDP 
def udp_seg(data):
    src_port , dest_port, size = struct.unpack('! H H 2x H',data[:8] )
    return src_port , dest_port, size, data[8:]

'''
    Format multiline 
'''
# format multi line
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x[:02x]'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix +line for line in textwrap.wrap(string,size)] )

main()










