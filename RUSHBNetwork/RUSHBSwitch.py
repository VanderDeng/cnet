import enum
import ipaddress
import math
import socket
import struct
import sys
import threading
from binascii import hexlify, unhexlify

LOCAL_HOST = "127.0.0.1"
TIME_OUT = 5.0

PACKET_MAX_LENGTH = 1500
DATA_MAX_LENGTH = 1488

DISCOVERY = 0x01
OFFER = 0x02
REQUEST = 0x03
ACKNOWLEDGE = 0x04
DATA_MODE = 0x05
IS_AVAILABLE = 0x06
AVAILABLE = 0x07
LOCATION_MODE = 0x08
DISTANCE = 0x09
CHUNKS_MODE = 0x0a
LAST_CHUNKS_MODE = 0x0b
INVALID = 0x00
AVAIL_MODES = [DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE, DATA_MODE, AVAILABLE, IS_AVAILABLE, LOCATION_MODE, DISTANCE,
               CHUNKS_MODE, LAST_CHUNKS_MODE]

# 最后改
N_ASSIGNED_IP = 'assigned_ip'
N_D_DISTANCE = 'direct_distance'
N_UDP_ADDR = 'udp_address'
N_SOCKET = 'socket'
N_TIMER = 'timer'
NEIGHBOURS = dict()

P_SWITCH = "switch"
P_DISTANCE = "distance"
PATH = dict()

DQ_PKT = "packet"
DQ_S = "socket"
DATA_QUEUE = dict()  # Data to send to adapter when it is available

# {source_ip: dataString}
DATA_COLLECTED = dict()  # Collect chunks of data for later concatenation

LATITUDE = None
LONGITUDE = None

TCP_NUMBERS = 0
UDP_NUMBERS = 0
UDP_MAX = 0
TCP_MAX = 0
MY_IP = None
TCP_IP = None
GLOBAL_IP = None

# Using Lock to prevent the race condition
lock = threading.Lock()


# class PacketType(enum.Enum):
#     DATA = 'DATA'
#     GREETING = 'GREETING'
#     DATA_COM = 'DATA_COM'
#     LOCATION = 'LOCATION'
#     BROADCAST = 'BROADCAST'


# def convert_reserved_value(val):
#     hex_val =
#     return unhexlify(hexlify(val.to_bytes(3, 'big')).decode('utf-8'))


# def assign_new_ip(pac_type):
#     global TCP_NUMBERS
#     global UDP_NUMBERS
#
#     if pac_type == "TCP":
#         # remember to handle special cases 0 - 255
#         next_ip = ipaddress.ip_address(
#             TCP_IP) + 1 + TCP_NUMBERS
#         TCP_NUMBERS += 1
#     elif pac_type == "UDP":
#         next_ip = ipaddress.ip_address(
#             MY_IP) + 1 + UDP_NUMBERS
#         UDP_NUMBERS += 1
#     return str(ipaddress.ip_address(next_ip))


# def ip_to_bin(ip):
#     return ' ' .join(format(int(x), '08b') for x in ip.split('.'))


# def prefix_matching(end_ip, ip_array):
#     end_ip_bin = ' ' .join(format(int(x), '08b') for x in end_ip.split('.'))
#     long_list = []
#     for ip in ip_array:
#         longest_item = 0
#         ip_bin = ' ' .join(format(int(x), '08b') for x in ip.split('.'))
#         for index, b in enumerate(end_ip_bin):
#             if ip_bin[index] == b:
#                 longest_item += 1
#             else:
#                 break
#         long_list.append(longest_item)
#     if long_list:
#         return ip_array[long_list.index(max(long_list))]
#     else:
#         return None


def greeting(data, pac_type=None):
    try:
        source_ip = data[:4]
        destination_ip = data[4:8]
        reserved = data[8:11]
        mode = data[11]
        if mode not in AVAIL_MODES:
            return None
    except IndexError:
        return None

    if pac_type is None:
        return source_ip, destination_ip, reserved, mode

    if pac_type == 'DATA' or pac_type == 'GREETING':
        send_data = data[12:]
        return source_ip, destination_ip, reserved, mode, send_data

    elif pac_type == 'DATA_COM':
        return source_ip, destination_ip, reserved, mode

    elif pac_type == 'LOCATION':
        latitude = data[12:14]
        longitude = data[14:16]
        return source_ip, destination_ip, reserved, mode, latitude, longitude

    elif pac_type == 'BROADCAST':
        target_ip = data[12:16]
        distance = data[16:20]
        return source_ip, destination_ip, reserved, mode, target_ip, distance


def mylog():
    pass


def greeting_recv(packet, client_type, service, protocol="TCP", udp_address=None, tcp_address=None):
    global NEIGHBOURS
    global TCP_NUMBERS
    global TCP_MAX
    global LATITUDE
    global LONGITUDE
    global tcp_socket
    global PATH
    global UDP_NUMBERS
    resp_packets = []
    try:
        (source_ip, destination_ip, reserved, mode, assigned_ip) = greeting(
            packet, 'GREETING')
    except (Exception,):
        return

    # 待修改
    if mode == DISCOVERY:
        if protocol == "UDP" and UDP_NUMBERS < UDP_MAX:
            new_src_ip = MY_IP
            next_ip = ipaddress.ip_address(MY_IP) + 1 + UDP_NUMBERS
            UDP_NUMBERS += 1
            assigned_ip = str(ipaddress.ip_address(next_ip))
            new_dst_ip = source_ip
            new_mode = OFFER
            offer_pkt = create_greeting_pkt(socket.inet_aton(new_src_ip), new_dst_ip, bytes(
                3), new_mode, (socket.inet_aton(assigned_ip),))
            service.sendto(offer_pkt, udp_address)
        elif protocol == "TCP" and TCP_NUMBERS < TCP_MAX:
            new_src_ip = TCP_IP
            next_ip = ipaddress.ip_address(TCP_IP) + 1 + TCP_NUMBERS
            TCP_NUMBERS += 1
            assigned_ip = str(ipaddress.ip_address(next_ip))
            new_dst_ip = source_ip
            new_mode = OFFER
            offer_pkt = create_greeting_pkt(socket.inet_aton(new_src_ip), new_dst_ip, bytes(
                3), new_mode, (socket.inet_aton(assigned_ip),))
            service.sendall(offer_pkt)

        resp_packets = [offer_pkt]

    elif mode == OFFER:
        # Send REQ, as a client that is not assigned IP yet
        new_src_ip = '0.0.0.0'
        new_dst_ip = source_ip
        new_mode = REQUEST
        req_pkt = create_greeting_pkt(socket.inet_aton(new_src_ip), new_dst_ip, bytes(
            3), new_mode, (assigned_ip,))
        if protocol == "TCP":
            service.sendall(req_pkt)
        else:
            service.sendto(req_pkt, udp_address)
        resp_packets = [req_pkt]

    elif mode == REQUEST:
        # Send ack
        if protocol == "TCP":
            new_src_ip = TCP_IP
            n_info = {N_ASSIGNED_IP: TCP_IP,
                      N_SOCKET: service, N_TIMER: threading.Timer(TIME_OUT, mylog)}
        elif protocol == "UDP":
            new_src_ip = MY_IP
            n_info = {N_ASSIGNED_IP: MY_IP,
                      N_SOCKET: service, N_UDP_ADDR: udp_address, N_TIMER: threading.Timer(TIME_OUT, mylog)}

        new_dst_ip = assigned_ip
        new_mode = ACKNOWLEDGE

        # Update NEIGHBOURS
        # if client_type == "server" and protocol == "UDP":
        NEIGHBOURS[socket.inet_ntoa(assigned_ip)] = n_info

        ack_pkt = create_greeting_pkt(socket.inet_aton(new_src_ip), new_dst_ip, bytes(
            3), new_mode, (assigned_ip,))

        if protocol == "TCP":
            service.sendall(ack_pkt)
        else:
            service.sendto(ack_pkt, udp_address)

    # When the server rcv the Location packet
    elif mode == ACKNOWLEDGE or (mode == LOCATION_MODE and client_type == "server"):
        if client_type == "client":
            # Update NEIGHBOURS
            n_info = {N_ASSIGNED_IP: socket.inet_ntoa(
                assigned_ip), N_SOCKET: service, N_TIMER: threading.Timer(TIME_OUT, mylog)}
            NEIGHBOURS[socket.inet_ntoa(source_ip)] = n_info
            # Update PATH
            new_src_ip = assigned_ip
        else:
            new_src_ip = socket.inet_aton(
                TCP_IP if protocol == "TCP" else MY_IP)

        # Send its Location back
        new_dst_ip = source_ip
        new_mode = LOCATION_MODE
        axis = struct.pack('>H', LATITUDE)
        yaxis = struct.pack('>H', LONGITUDE)
        location_pkt = create_greeting_pkt(
            new_src_ip, new_dst_ip, bytes(3), new_mode, (axis, yaxis,))

        if protocol == "TCP":
            service.sendall(location_pkt)
        else:
            service.sendto(location_pkt, udp_address)

    elif mode == DATA_MODE or mode == CHUNKS_MODE or mode == LAST_CHUNKS_MODE:
        # Send DATA packet:
        packet_len = len(packet)
        packet_chunks = []
        # First local switch

        if packet_len > PACKET_MAX_LENGTH:
            data_len = packet_len - 12
            num_full_packets = math.floor(data_len / DATA_MAX_LENGTH)
            # Chunks of packet
            for i in range(num_full_packets):
                new_reserved = unhexlify(hexlify(i * DATA_MAX_LENGTH.to_bytes(3, 'big')).decode('utf-8'))
                new_mode = CHUNKS_MODE
                data_chunk = assigned_ip[i * DATA_MAX_LENGTH:(DATA_MAX_LENGTH * (i + 1))]
                packet_chunk = create_greeting_pkt(
                    source_ip, destination_ip, new_reserved, new_mode, (data_chunk,))
                packet_chunks.append(packet_chunk)
            # Last packet chunk
            consumed_data_len = num_full_packets * DATA_MAX_LENGTH
            remain_data_len = data_len - consumed_data_len
            if remain_data_len > 0:
                new_reserved = unhexlify(hexlify(DATA_MAX_LENGTH.to_bytes(3, 'big')).decode('utf-8'))
                new_mode = LAST_CHUNKS_MODE
                remain_data = assigned_ip[consumed_data_len:data_len]
                last_packet_chunk = create_greeting_pkt(
                    source_ip, destination_ip, new_reserved, new_mode, (remain_data,))
                packet_chunks.append(last_packet_chunk)
        else:
            packet_chunks = [packet]

        # Switch receives chunks of data whose destination is its ip addr
        o_dest_ip = socket.inet_ntoa(destination_ip)
        o_src_ip = socket.inet_ntoa(source_ip)
        if o_dest_ip == TCP_IP or o_dest_ip == MY_IP:  # The switch received the message
            data_b = assigned_ip
            message = data_b.decode()
            if mode == DATA_MODE:
                print(
                    f'\b\bReceived from {socket.inet_ntoa(source_ip)}: {message}', flush=True)
                print("> ", end="", flush=True)
            elif mode == CHUNKS_MODE:
                if o_src_ip not in DATA_COLLECTED:
                    DATA_COLLECTED[o_src_ip] = message
                else:
                    DATA_COLLECTED[o_src_ip] += message
            elif mode == LAST_CHUNKS_MODE:
                DATA_COLLECTED[o_src_ip] += message
                print(
                    f'\b\bReceived from {socket.inet_ntoa(source_ip)}: {DATA_COLLECTED[o_src_ip]}', flush=True)
                print("> ", end="", flush=True)

            return

        # Determine next switch to send
        if o_dest_ip not in PATH.keys():
            # Find in the NEIGHBOUTS the assigned ip that has given socket
            this_assigned_ip = None
            for n_ip in NEIGHBOURS:
                if NEIGHBOURS[n_ip][N_SOCKET] == service:
                    this_assigned_ip = n_ip
            candidates = list(NEIGHBOURS.keys())
            candidates.remove(this_assigned_ip)
            # next ip except for the sending ip

            end_ip_bin = ' '.join(format(int(x), '08b') for x in o_dest_ip.split('.'))
            long_list = []
            for ip in candidates:
                longest_item = 0
                ip_bin = ' '.join(format(int(x), '08b') for x in ip.split('.'))
                for index, b in enumerate(end_ip_bin):
                    if ip_bin[index] == b:
                        longest_item += 1
                    else:
                        break
                long_list.append(longest_item)
            if long_list:
                next_ip = candidates[long_list.index(max(long_list))]
            else:
                next_ip = None

        else:
            next_ip = PATH[o_dest_ip][P_SWITCH]
            if not next_ip:
                next_ip = o_dest_ip

        sock_to_send = NEIGHBOURS[next_ip][N_SOCKET]

        # Update Data queue and send AVAILABLE
        if MY_IP and TCP_IP:
            next_ip = o_dest_ip
            if next_ip not in NEIGHBOURS:
                return

        # Update the data queue for next switch
        if next_ip not in DATA_QUEUE:
            DATA_QUEUE[next_ip] = {
                DQ_PKT: packet_chunks, DQ_S: sock_to_send}
        elif next_ip in DATA_QUEUE and not DATA_QUEUE[next_ip][DQ_PKT]:
            DATA_QUEUE[next_ip][DQ_PKT] = packet_chunks
        else:
            DATA_QUEUE[next_ip][DQ_PKT].extend(packet_chunks)

        # Send AVAILABLE to the next switch, save packets to queue if data chunks
        if mode == CHUNKS_MODE:
            return

        dest_timer = NEIGHBOURS[next_ip][N_TIMER]
        if not dest_timer.is_alive():  # Check the timer
            new_mode = IS_AVAILABLE
            is_avail_packet = create_greeting_pkt(
                socket.inet_aton(NEIGHBOURS[next_ip][N_ASSIGNED_IP]), socket.inet_aton(next_ip), bytes(3), new_mode,
                (bytes(),))
            if TCP_IP and MY_IP:
                udp_address = NEIGHBOURS[next_ip][N_UDP_ADDR]
                sock_to_send.sendto(is_avail_packet, udp_address)
            else:
                sock_to_send.sendall(is_avail_packet)

            try:
                dest_timer.start()
            except RuntimeError:
                dest_timer = threading.Timer(TIME_OUT, mylog)
                dest_timer.start()
            return

    elif mode == IS_AVAILABLE:
        new_src_ip = destination_ip
        new_dst_ip = source_ip
        new_mode = AVAILABLE
        avail_pkt = create_greeting_pkt(new_src_ip, new_dst_ip, bytes(
            3), new_mode, (bytes(),))
        if protocol == "UDP":
            service.sendto(avail_pkt, udp_address)
        else:
            service.sendall(avail_pkt)

    elif mode == AVAILABLE:
        sock_to_send = DATA_QUEUE[socket.inet_ntoa(source_ip)][DQ_S]
        packet_list = DATA_QUEUE[socket.inet_ntoa(source_ip)][DQ_PKT]
        for packet in packet_list:
            if protocol == "UDP":
                sock_to_send.sendto(packet, udp_address)
            else:
                sock_to_send.sendall(packet)
        # reset data queue
        packet_list = []

    # Calc distance and broadcast
    # 𝑑𝑖𝑠𝑡𝑎𝑛𝑐𝑒 = √(465 − 2)2 + (784 − 5)2 = 906.20 ≈ 906
    if mode == LOCATION_MODE:
        try:
            (source_ip, destination_ip, reserved, mode, axis, yaxis) = greeting(
                packet, 'LOCATION')  # bytes
        except:
            return

        new_mode = DISTANCE
        rcv_latt = int.from_bytes(axis, 'big')
        rcv_longt = int.from_bytes(yaxis, 'big')
        distance = math.floor(
            math.sqrt((LATITUDE - rcv_latt) ** 2 + (LONGITUDE - rcv_longt) ** 2))

        if distance > 1000:
            return

        # Update NEIGHBOURS direct distance
        NEIGHBOURS[socket.inet_ntoa(source_ip)][N_D_DISTANCE] = distance
        # Update PATH distance
        if socket.inet_ntoa(source_ip) not in PATH or (
                socket.inet_ntoa(source_ip) in PATH and PATH[socket.inet_ntoa(source_ip)][P_DISTANCE] > distance):
            PATH[socket.inet_ntoa(source_ip)] = {
                P_SWITCH: None, P_DISTANCE: distance}
        if MY_IP and client_type == "server":  # Local switch with 2 IP recv location
            # Send distance of UDP port to global switch
            new_src_ip = destination_ip
            new_dest_ip = source_ip
            distance_pkt = create_greeting_pkt(new_src_ip, new_dest_ip, bytes(
                3), new_mode, (socket.inet_aton(MY_IP), distance.to_bytes(4, byteorder='big'),))
            service.sendall(distance_pkt)
            return

        # Broadcast distance to all of the NEIGHBOURS
        for n_ip in NEIGHBOURS.keys():
            if n_ip == socket.inet_ntoa(source_ip):
                continue
            new_src_ip = NEIGHBOURS[n_ip][N_ASSIGNED_IP]
            new_dst_ip = n_ip
            distance_b = (
                    distance + NEIGHBOURS[n_ip][N_D_DISTANCE]).to_bytes(4, byteorder='big')
            new_pkt = create_greeting_pkt(socket.inet_aton(
                new_src_ip), socket.inet_aton(new_dst_ip), bytes(3), new_mode, (source_ip, distance_b,))

            skt = NEIGHBOURS[n_ip][N_SOCKET]
            if protocol == "TCP":
                skt.sendall(new_pkt)
            else:
                skt.sendto(new_pkt, udp_address)
            resp_packets.append(new_pkt)

    elif mode == DISTANCE:
        try:
            (source_ip, destination_ip, reserved, mode, target_ip,
             distance) = greeting(packet, 'BROADCAST')
        except:
            return

        new_mode = DISTANCE
        o_src_ip = socket.inet_ntoa(source_ip)
        o_dst_ip = socket.inet_ntoa(destination_ip)
        o_target_ip = socket.inet_ntoa(target_ip)
        int_distance = int.from_bytes(distance, "big")

        # Already in PATH with smaller distance
        if (o_target_ip in PATH and PATH[o_target_ip][P_SWITCH] == o_src_ip and PATH[o_target_ip][
            P_DISTANCE] < int_distance):
            return

        # Update PATH if this S is not the target S and target S is not in PATH or target S already in PATH,
        # but with larger distance
        if o_target_ip != TCP_IP and (not o_target_ip in PATH) or (
                o_target_ip in PATH and PATH[o_target_ip][P_DISTANCE] > int_distance):
            if not MY_IP or (MY_IP and o_target_ip != MY_IP):
                PATH[o_target_ip] = {
                    P_SWITCH: o_src_ip, P_DISTANCE: int_distance}

        # Brc to NEIGHBOURS
        for n_ip in NEIGHBOURS.keys():
            # Else if the neighbour'service ip addr != src,dest,target
            # Send the BRC to it
            if n_ip != o_src_ip and n_ip != o_dst_ip and n_ip != o_target_ip:
                new_src_ip = NEIGHBOURS[n_ip][N_ASSIGNED_IP]
                new_dst_ip = n_ip
                new_d_int = int_distance + NEIGHBOURS[n_ip][N_D_DISTANCE]
                new_d = new_d_int.to_bytes(4, byteorder='big')
                new_pkt = create_greeting_pkt(socket.inet_aton(
                    new_src_ip), socket.inet_aton(new_dst_ip), bytes(3), new_mode, (target_ip, new_d,))
                skt = NEIGHBOURS[n_ip][N_SOCKET]
                if protocol == "TCP":
                    skt.sendall(new_pkt)
                else:
                    skt.sendto(new_pkt, udp_address)

    return resp_packets


def udp_connect():
    while True:
        # a packet with a maximum size of 55296 bytes.
        packet, address = self_socket.recvfrom(55296)
        u = threading.Thread(target=udp_connected, args=(packet, address,))
        u.start()


def udp_connected(packet, address):
    lock.acquire()
    greeting_recv(packet, "server", self_socket, protocol="UDP", udp_address=address)
    lock.release()


def create_greeting_pkt(source_ip, destination_ip, reserved, mode, data=None):
    packets = bytearray()
    mode = bytes([mode])
    packets += (source_ip + destination_ip + reserved + mode)
    for i in data:
        packets += i
    return packets


def create_connection(prot_code):
    pkt_data = create_greeting_pkt(socket.inet_aton('0.0.0.0'), socket.inet_aton(
        '0.0.0.0'), bytes(3), DISCOVERY, data=(socket.inet_aton('0.0.0.0'),))

    service = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    service.connect((LOCAL_HOST, prot_code))
    service.sendall(pkt_data)

    while True:
        data = service.recv(PACKET_MAX_LENGTH)
        lock.acquire()
        greeting_recv(data, "client", service)
        lock.release()


def tcp_connect():
    while True:
        connect, address = tcp_socket.accept()
        tcp_handle_thread = threading.Thread(target=tcp_connected, args=(connect, address,))
        tcp_handle_thread.start()


def tcp_connected(connect, address):
    with connect:
        while True:
            packet = connect.recv(PACKET_MAX_LENGTH)
            greeting_recv(packet, "server", connect)


def task_connect(order):
    if order.split(" ", 1)[0] == "connect" and len(sys.argv) < 6:
        end_port = int(order.split(" ", 1)[1])
        create_connection(end_port)


def set_max(ip):
    return 2 ** (32 - int(ip)) - 2


# # Read params
# params = sys.argv
# switch_type = sys.argv[1]
LOCATION = [LATITUDE, LONGITUDE]
LATITUDE = sys.argv[3]
LONGITUDE = sys.argv[4]

CONNECTION_INFO = (LOCAL_HOST, 0)

if sys.argv[1] == "local":
    LEN_IP = sys.argv[2]
    LATITUDE = sys.argv[3]
    LONGITUDE = sys.argv[4]
    if len(sys.argv) == 6:
        GLOBAL_IP = sys.argv[3]
        LATITUDE = sys.argv[4]
        LONGITUDE = sys.argv[5]
else:
    GLOBAL_IP = sys.argv[2]

LATITUDE = int(LATITUDE)
LONGITUDE = int(LONGITUDE)

if sys.argv[1] == "local":
    LEN_IP = LEN_IP.split("/")
    MY_IP = LEN_IP[0]
    UDP_MAX = set_max(LEN_IP[1])
    self_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self_socket.bind(CONNECTION_INFO)
    udp_port = self_socket.getsockname()[1]

    # print(udp_port, flush=True)
    print(self_socket.getsockname()[1])
    sys.stdout.flush()

    u = threading.Thread(target=udp_connect)
    u.start()

if sys.argv[1] == "local" and len(sys.argv) == 6 or sys.argv[1] == "global":
    GLOBAL_IP = GLOBAL_IP.split("/")
    TCP_IP = GLOBAL_IP[0]
    TCP_MAX = set_max(GLOBAL_IP[1])
    # TCP_MAX = 2 ** (32 - int(GLOBAL_IP[1])) - 2

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind(CONNECTION_INFO)
    tcp_socket.listen()

    # tcp_port = tcp_socket.getsockname()[1]
    # print(tcp_port, flush=True)
    print(tcp_socket.getsockname()[1])
    sys.stdout.flush()

    t = threading.Thread(target=tcp_connect)
    t.start()

while True:
    try:
        task = input("> ")
        task_t = threading.Thread(target=task_connect, args=(task,))
        task_t.start()
    except EOFError:
        break
