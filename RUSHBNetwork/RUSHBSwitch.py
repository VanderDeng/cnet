import math
import socket
import struct
import sys
import ipaddress
import threading
from binascii import hexlify, unhexlify

LOCAL_HOST = "127.0.0.1"
TIME_OUT = 5.0

DATA_MAX_LENGTH = 1488
CAL_DIFF = 12
MAX_DIS = 1000

DISCOVERY = 0x01
OFFER = 0x02
REQUEST = 0x03
ACKNOWLEDGE = 0x04
DATA = 0x05
IS_AVAILABLE = 0x06
AVAILABLE = 0x07
LOCATIONS = 0x08
DISTANCE = 0x09
MORE_PKT = 0x0a
END_PKT = 0x0b
INVALID = 0x00
AVAIL_MODES = [DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE, DATA, AVAILABLE, IS_AVAILABLE, LOCATIONS, DISTANCE,
               MORE_PKT, END_PKT]

LATITUDE = None
LONGITUDE = None
TCP_NUMBERS = 0
UDP_NUMBERS = 0
UDP_MAX = 0
TCP_MAX = 0
MY_IP = None
TCP_IP = None
GLOBAL_IP = None

CON_IP = 'asset_ip'
CON_ADDRESS = 'udp_address'
CON_SOCKET = 'socket'
CON_TIMER = 'timer'
PKT_SWITCH = "switch"
PKT_DISTANCE = "distance"
SET_PACKET = "packet"
SET_SOCKET = "socket"
PKT_LIST = dict()
DATA_OBJECT = dict()
PKT_PATH = dict()
NEIBERLIST = dict()

TYPE = ["TCP", "UDP"]

lock = threading.Lock()


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


def ip_tans(ip, num):
    res = ipaddress.ip_address(ip) + 1 + num

    return res


def ip_format(ip):
    res = str(ipaddress.ip_address(ip))

    return res


def cal_distance(lat, log):
    res = math.floor(math.sqrt((LATITUDE - lat) ** 2 + (LONGITUDE - log) ** 2))

    return res


def greeting_recv(packet, client_type, service, pro_type="TCP", udp_address=None):
    global UDP_NUMBERS
    global TCP_NUMBERS
    global NEIBERLIST
    global tcp_socket
    global TCP_MAX
    global PKT_PATH
    global LATITUDE
    global LONGITUDE
    global TYPE
    resp_packets = []
    try:
        (source_ip, destination_ip, reserved, mode, asset_ip) = greeting(packet, 'GREETING')
    except (Exception,):
        return

    # Separate according to different modes
    # DISCOVERY
    if mode == DISCOVERY:
        if pro_type == TYPE[0] and TCP_NUMBERS < TCP_MAX:
            from_ip = TCP_IP
            second_ip = ip_tans(TCP_IP, TCP_NUMBERS)
            TCP_NUMBERS = TCP_NUMBERS + 1
            asset_ip = ip_format(second_ip)
            end_ip = source_ip
            cur_mode = OFFER
            given_packet = create_greeting_pkt(socket.inet_aton(from_ip), end_ip, bytes(3), cur_mode, (
                socket.inet_aton(asset_ip),))
            service.sendall(given_packet)
        elif pro_type == TYPE[1] and UDP_NUMBERS < UDP_MAX:
            from_ip = MY_IP
            second_ip = ip_tans(MY_IP, UDP_NUMBERS)
            UDP_NUMBERS = UDP_NUMBERS + 1
            asset_ip = ip_format(second_ip)
            end_ip = source_ip
            cur_mode = OFFER
            given_packet = create_greeting_pkt(socket.inet_aton(from_ip), end_ip, bytes(3), cur_mode, (
                socket.inet_aton(asset_ip),))
            service.sendto(given_packet, udp_address)
        resp_packets = [given_packet]

    # OFFER
    elif mode == OFFER:
        cur_mode = REQUEST
        from_ip = '0.0.0.0'
        end_ip = source_ip
        if pro_type == TYPE[0]:
            service.sendall(create_greeting_pkt(socket.inet_aton(from_ip), end_ip, bytes(3), cur_mode, (asset_ip,)))
        else:
            service.sendto(create_greeting_pkt(socket.inet_aton(from_ip), end_ip, bytes(3), cur_mode, (asset_ip,)),
                           udp_address)
        resp_packets = [create_greeting_pkt(socket.inet_aton(from_ip), end_ip, bytes(3), cur_mode, (asset_ip,))]

    # REQUEST
    elif mode == REQUEST:
        if pro_type == TYPE[0]:
            from_ip = TCP_IP
            con_obj = {CON_IP: TCP_IP, CON_SOCKET: service, CON_TIMER: threading.Timer(TIME_OUT, mylog)}
        elif pro_type == TYPE[1]:
            from_ip = MY_IP
            con_obj = {CON_IP: MY_IP, CON_SOCKET: service, CON_ADDRESS: udp_address, CON_TIMER: threading.Timer(
                TIME_OUT, mylog)}

        end_ip = asset_ip
        cur_mode = ACKNOWLEDGE
        NEIBERLIST[socket.inet_ntoa(asset_ip)] = con_obj
        ack_pkt = create_greeting_pkt(socket.inet_aton(from_ip), end_ip, bytes(3), cur_mode, (asset_ip,))

        if pro_type == TYPE[0]:
            service.sendall(ack_pkt)
        else:
            service.sendto(ack_pkt, udp_address)

    # ACKNOWLEDGE
    elif mode == ACKNOWLEDGE or (mode == LOCATIONS and client_type == "server"):
        if client_type == "client":
            con_obj = {CON_IP: socket.inet_ntoa(asset_ip), CON_SOCKET: service, CON_TIMER: threading.Timer(
                TIME_OUT, mylog)}
            NEIBERLIST[socket.inet_ntoa(source_ip)] = con_obj
            from_ip = asset_ip
        else:
            from_ip = socket.inet_aton(TCP_IP if pro_type == TYPE[0] else MY_IP)
        end_ip = source_ip
        cur_mode = LOCATIONS
        axis = struct.pack('>H', LATITUDE)
        yaxis = struct.pack('>H', LONGITUDE)
        location_pkt = create_greeting_pkt(from_ip, end_ip, bytes(3), cur_mode, (axis, yaxis,))

        if pro_type == TYPE[0]:
            service.sendall(location_pkt)
        else:
            service.sendto(location_pkt, udp_address)

    elif mode == DATA or mode == MORE_PKT or mode == END_PKT:
        pkt_length = len(packet)
        pkt_sums = []

        if pkt_length > 1500:
            data_length = pkt_length - CAL_DIFF
            all_pkts = math.floor(data_length / DATA_MAX_LENGTH)
            for i in range(all_pkts):
                cur_reserve = unhexlify(hexlify(i * DATA_MAX_LENGTH.to_bytes(3, byteorder='big')).decode('utf-8'))
                cur_mode = MORE_PKT
                data_chunk = asset_ip[i * DATA_MAX_LENGTH:(DATA_MAX_LENGTH * (i + 1))]
                packet_chunk = create_greeting_pkt(source_ip, destination_ip, cur_reserve, cur_mode, (data_chunk,))
                pkt_sums.append(packet_chunk)
            used_length = all_pkts * DATA_MAX_LENGTH
            last_length = data_length - used_length
            if last_length > 0:
                cur_reserve = unhexlify(hexlify(DATA_MAX_LENGTH.to_bytes(3, byteorder='big')).decode('utf-8'))
                cur_mode = END_PKT
                remain_data = asset_ip[used_length:data_length]
                last_packet_chunk = create_greeting_pkt(source_ip, destination_ip, cur_reserve, cur_mode,
                                                        (remain_data,))
                pkt_sums.append(last_packet_chunk)
        else:
            pkt_sums = [packet]

        origin_ip = socket.inet_ntoa(destination_ip)
        origin_sip = socket.inet_ntoa(source_ip)
        if origin_ip == TCP_IP or origin_ip == MY_IP:
            object_pass = asset_ip
            content = object_pass.decode()
            if mode == DATA:
                print(f'\b\bReceived from {socket.inet_ntoa(source_ip)}: {content}')
                sys.stdout.flush()
                print("> ", end="")
                sys.stdout.flush()
            elif mode == MORE_PKT:
                if origin_sip not in DATA_OBJECT:
                    DATA_OBJECT[origin_sip] = content
                else:
                    DATA_OBJECT[origin_sip] += content
            elif mode == END_PKT:
                print(f'\b\bReceived from {socket.inet_ntoa(source_ip)}: {DATA_OBJECT[origin_sip]}')
                sys.stdout.flush()
                print("> ", end="")
                sys.stdout.flush()
                DATA_OBJECT[origin_sip] += content
            return

        if origin_ip not in PKT_PATH.keys():
            cur_set_ip = None
            for neibor_ip in NEIBERLIST:
                if NEIBERLIST[neibor_ip]['socket'] == service:
                    cur_set_ip = neibor_ip
            holdings = list(NEIBERLIST.keys())
            holdings.remove(cur_set_ip)
            end_ip_bin = ' '.join(format(int(x), '08b') for x in origin_ip.split('.'))
            long_list = []
            for ip in holdings:
                longest_item = 0
                ip_bin = ' '.join(format(int(x), '08b') for x in ip.split('.'))
                for index, b in enumerate(end_ip_bin):
                    if ip_bin[index] == b:
                        longest_item += 1
                    else:
                        break
                long_list.append(longest_item)
            if long_list:
                second_ip = holdings[long_list.index(max(long_list))]
            else:
                second_ip = None

        else:
            second_ip = PKT_PATH[origin_ip][PKT_SWITCH]
            if not second_ip:
                second_ip = origin_ip

        socket_sent = NEIBERLIST[second_ip]['socket']

        if MY_IP and TCP_IP:
            second_ip = origin_ip
            if second_ip not in NEIBERLIST:
                return

        if second_ip not in PKT_LIST:
            PKT_LIST[second_ip] = {SET_PACKET: pkt_sums, SET_SOCKET: NEIBERLIST[second_ip]['socket']}
        elif second_ip in PKT_LIST and not PKT_LIST[second_ip]["packet"]:
            PKT_LIST[second_ip]["packet"] = pkt_sums
        else:
            PKT_LIST[second_ip]["packet"].extend(pkt_sums)

        if mode == MORE_PKT:
            return

        finish_time = NEIBERLIST[second_ip][CON_TIMER]
        if not finish_time.is_alive():
            cur_mode = IS_AVAILABLE
            packet_available = create_greeting_pkt(socket.inet_aton(NEIBERLIST[second_ip][CON_IP]),
                                                   socket.inet_aton(second_ip), bytes(3), cur_mode, (bytes(),))
            if TCP_IP and MY_IP:
                udp_address = NEIBERLIST[second_ip][CON_ADDRESS]
                socket_sent.sendto(packet_available, udp_address)
            else:
                socket_sent.sendall(packet_available)

            try:
                finish_time.start()
            except RuntimeError:
                finish_time = threading.Timer(TIME_OUT, mylog)
                finish_time.start()
            return

    elif mode == IS_AVAILABLE:
        from_ip = destination_ip
        end_ip = source_ip
        cur_mode = AVAILABLE
        avail_pkt = create_greeting_pkt(from_ip, end_ip, bytes(3), cur_mode, (bytes(),))
        if pro_type == TYPE[1]:
            service.sendto(avail_pkt, udp_address)
        else:
            service.sendall(avail_pkt)

    elif mode == AVAILABLE:
        socket_sent = PKT_LIST[socket.inet_ntoa(source_ip)][SET_SOCKET]
        packet_list = PKT_LIST[socket.inet_ntoa(source_ip)][SET_PACKET]
        for packet in packet_list:
            if pro_type == TYPE[1]:
                socket_sent.sendto(packet, udp_address)
            else:
                socket_sent.sendall(packet)

    # Calc distance and broadcast
    # 𝑑𝑖𝑠𝑡𝑎𝑛𝑐𝑒 = √(465 − 2)2 + (784 − 5)2 = 906.20 ≈ 906
    if mode == LOCATIONS:
        try:
            (source_ip, destination_ip, reserved, mode, axis, yaxis) = greeting(packet, 'LOCATION')
        except (Exception,):
            return

        cur_mode = DISTANCE
        rcv_latt = int.from_bytes(axis, byteorder='big')
        rcv_longt = int.from_bytes(yaxis, byteorder='big')
        distance = cal_distance(rcv_latt, rcv_longt)

        if distance > MAX_DIS:
            return

        NEIBERLIST[socket.inet_ntoa(source_ip)]['direct_distance'] = distance
        if socket.inet_ntoa(source_ip) not in PKT_PATH or (
                socket.inet_ntoa(source_ip) in PKT_PATH and PKT_PATH[socket.inet_ntoa(source_ip)][PKT_DISTANCE] > distance):
            PKT_PATH[socket.inet_ntoa(source_ip)] = {PKT_SWITCH: None, PKT_DISTANCE: distance}
        if MY_IP and client_type == "server":
            from_ip = destination_ip
            new_dest_ip = source_ip
            distance_pkt = create_greeting_pkt(from_ip, new_dest_ip, bytes(3), cur_mode, (
                socket.inet_aton(MY_IP), distance.to_bytes(4, byteorder='big'),))
            service.sendall(distance_pkt)
            return

        for neibor_ip in NEIBERLIST.keys():
            if neibor_ip == socket.inet_ntoa(source_ip):
                continue
            from_ip = NEIBERLIST[neibor_ip][CON_IP]
            end_ip = neibor_ip
            next_dis = (distance + NEIBERLIST[neibor_ip]['direct_distance']).to_bytes(4, byteorder='big')
            cur_pkt = create_greeting_pkt(socket.inet_aton(from_ip), socket.inet_aton(end_ip), bytes(3), cur_mode,
                                          (source_ip, next_dis,))

            n_socket = NEIBERLIST[neibor_ip][CON_SOCKET]
            if pro_type == TYPE[0]:
                n_socket.sendall(cur_pkt)
            else:
                n_socket.sendto(cur_pkt, udp_address)
            resp_packets.append(cur_pkt)

    elif mode == DISTANCE:
        try:
            (source_ip, destination_ip, reserved, mode, target_ip,
             distance) = greeting(packet, 'BROADCAST')
        except (Exception,):
            return

        cur_mode = DISTANCE
        origin_sip = socket.inet_ntoa(source_ip)
        fin_ip = socket.inet_ntoa(destination_ip)
        fin_aim_ip = socket.inet_ntoa(target_ip)
        int_distance = int.from_bytes(distance, byteorder='big')

        if fin_aim_ip in PKT_PATH and PKT_PATH[fin_aim_ip][PKT_SWITCH] == origin_sip and PKT_PATH[fin_aim_ip][PKT_DISTANCE] < int_distance:
            return

        if fin_aim_ip != TCP_IP and (fin_aim_ip not in PKT_PATH) or (
                fin_aim_ip in PKT_PATH and PKT_PATH[fin_aim_ip][PKT_DISTANCE] > int_distance):
            if not MY_IP or (MY_IP and fin_aim_ip != MY_IP):
                PKT_PATH[fin_aim_ip] = {PKT_SWITCH: origin_sip, PKT_DISTANCE: int_distance}

        for neibor_ip in NEIBERLIST.keys():
            if neibor_ip != origin_sip and neibor_ip != fin_ip and neibor_ip != fin_aim_ip:
                from_ip = NEIBERLIST[neibor_ip][CON_IP]
                end_ip = neibor_ip
                cur_dis_format = int_distance + NEIBERLIST[neibor_ip]['direct_distance']
                cur_distance = cur_dis_format.to_bytes(4, byteorder='big')
                cur_pkt = create_greeting_pkt(socket.inet_aton(from_ip), socket.inet_aton(end_ip), bytes(3), cur_mode, (
                    target_ip, cur_distance,))
                n_socket = NEIBERLIST[neibor_ip][CON_SOCKET]
                if pro_type == TYPE[0]:
                    n_socket.sendall(cur_pkt)
                else:
                    n_socket.sendto(cur_pkt, udp_address)

    return resp_packets


def udp_connect():
    while True:
        # a packet with a maximum size of 55296 bytes.
        packet, address = self_socket.recvfrom(55296)
        u = threading.Thread(target=udp_connected, args=(packet, address,))
        u.start()


def udp_connected(packet, address):
    lock.acquire()
    greeting_recv(packet, "server", self_socket, pro_type="UDP", udp_address=address)
    lock.release()


def create_greeting_pkt(source_ip, destination_ip, reserved, mode, data=None):
    packets = bytearray()
    mode = bytes([mode])
    packets += (source_ip + destination_ip + reserved + mode)
    for i in data:
        packets += i
    return packets


def create_connection(prot_code):
    pkt_data = create_greeting_pkt(socket.inet_aton('0.0.0.0'), socket.inet_aton('0.0.0.0'), bytes(3), DISCOVERY,
                                   data=(socket.inet_aton('0.0.0.0'),))

    service = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    service.connect((LOCAL_HOST, prot_code))
    service.sendall(pkt_data)

    while True:
        data = service.recv(1500)
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
            packet = connect.recv(1500)
            greeting_recv(packet, "server", connect)


def task_connect(order):
    if order.split(" ", 1)[0] == "connect" and len(sys.argv) < 6:
        end_port = int(order.split(" ", 1)[1])
        create_connection(end_port)


def set_max(ip):
    return 2 ** (32 - int(ip)) - 2


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
    print(self_socket.getsockname()[1])
    sys.stdout.flush()

    u = threading.Thread(target=udp_connect)
    u.start()

if sys.argv[1] == "local" and len(sys.argv) == 6 or sys.argv[1] == "global":
    GLOBAL_IP = GLOBAL_IP.split("/")
    TCP_IP = GLOBAL_IP[0]
    TCP_MAX = set_max(GLOBAL_IP[1])

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind(CONNECTION_INFO)
    tcp_socket.listen()

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
