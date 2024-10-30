import json
import sys
import hashlib
import requests
import socket
import struct
import os
import bencodepy
import math
import random
import threading
import urllib.parse
# import requests - available if you need it!
# bc = bencodepy.Bencode(encoding="utf-8")


def decode_string(bencoded_value):
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    length = int(bencoded_value[:first_colon_index].decode())
    start_index = first_colon_index + 1
    try:
        return bencoded_value[start_index:start_index + length].decode('utf-8'), bencoded_value[start_index+length:]
    except:
        return bencoded_value[start_index:start_index + length], bencoded_value[start_index+length:]
def decode_integer(bencoded_value):
    first_e_index = bencoded_value.find(b"e")
    if first_e_index == -1:
        raise ValueError("Invalid encoded value")
    decoded_string = bencoded_value[1:first_e_index].decode()
    return int(decoded_string), bencoded_value[first_e_index+1:]
def decode_list(bencoded_value):
    decoded_list = []
    i = 1
    while bencoded_value[i] != ord('e'):
        element, remaining = decode_bencode(bencoded_value[i:])
        decoded_list.append(element)
        i = len(bencoded_value) - len(remaining)
    
    return decoded_list, bencoded_value[i+1:]
def decode_dict(bencoded_value):
    decoded_dict = {}
    i = 1
    while bencoded_value[i] != ord('e'):
        key, remaining = decode_bencode(bencoded_value[i:])
        i = len(bencoded_value) - len(remaining)
        value, remaining = decode_bencode(bencoded_value[i:])
        i = len(bencoded_value) - len(remaining)
        decoded_dict[key] = value
    
    return decoded_dict, bencoded_value[i+1:]     
    
def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        return decode_string(bencoded_value)
    elif chr(bencoded_value[0]) == 'i':
        return decode_integer(bencoded_value)
    elif chr(bencoded_value[0]) == 'l':
        return decode_list(bencoded_value)    
    elif chr(bencoded_value[0]) == 'd':
        return decode_dict(bencoded_value)      
    else:
        raise NotImplementedError("Only strings and numbers are supported at the moment")
def get_decoded_value(bencoded_file):
    f = open(bencoded_file, "rb")
    bencoded_value = f.read()
    f.close()
    decoded_value,_ = decode_bencode(bencoded_value)
    return decoded_value
def announce_url(decoded_value):
    return decoded_value['announce']
def get_info_dict(decoded_value):
    return decoded_value['info']
def get_sha_info(info_dict):
    bencoded_info_dict = bencodepy.encode(info_dict)
    return hashlib.sha1(bencoded_info_dict).hexdigest()
def url_encode(info_hash):
    split_string = ''.join(['%' + info_hash[i:i+2] for i in range(0,len(info_hash),2)])
    return split_string
def ping_peer_torrent(peer_ip, peer_port, info_hash, peer_id, s):
    info_hash = bytes.fromhex(info_hash)
    s.connect((peer_ip,peer_port))
        
    protocol_length = 19
    protocol_length_bytes = protocol_length.to_bytes(1,byteorder='big')
    s.sendall(protocol_length_bytes)
    
    message = 'BitTorrent protocol'
    s.sendall(message.encode('utf-8'))
    
    reserved_bytes = b'\x00' * 8
    s.sendall(reserved_bytes)
    
    s.sendall(info_hash)
    
    s.sendall(peer_id.encode('utf-8'))
    
    s.recv(1)
    s.recv(19)
    s.recv(8)
    s.recv(20)
    return s.recv(20).hex()
def ping_peer_magnet(peer_ip, peer_port, info_hash, peer_id, s):
    info_hash = bytes.fromhex(info_hash)
    s.connect((peer_ip,peer_port))
        
    protocol_length = 19
    protocol_length_bytes = protocol_length.to_bytes(1,byteorder='big')
    s.sendall(protocol_length_bytes)
    
    message = 'BitTorrent protocol'
    s.sendall(message.encode('utf-8'))
    
    reserved_bytes = b'\x00\x00\x00\x00\x00\x10\x00\x00'
    s.sendall(reserved_bytes)
    
    s.sendall(info_hash)
    
    s.sendall(peer_id.encode('utf-8'))
    
    s.recv(1)
    s.recv(19)
    s.recv(8)
    s.recv(20)
    return s.recv(20).hex()
    
def get_peer_address_torrent(bencoded_file):
    decoded_value = get_decoded_value(bencoded_file)
    url = announce_url(decoded_value)
    info_dict = get_info_dict(decoded_value)
    sha_info_hash = get_sha_info(info_dict)
    
    encoded_hash = url_encode(sha_info_hash)
    peer_id = '3a5f9c1e2d4a8e3b0f6c'
    port = 6881
    uploaded = 0
    downloaded = 0
    left = info_dict['length']
    compact = 1
    
    query_string = (
        f"info_hash={encoded_hash}&"
        f"peer_id={peer_id}&"
        f"port={port}&"
        f"uploaded={uploaded}&"
        f"downloaded={downloaded}&"
        f"left={left}&"
        f"compact={compact}"
    )
    
    complete_url = f"{url}?{query_string}"
    r = requests.get(complete_url)
    decoded_dict,_ = decode_bencode(r.content)
    peers = decoded_dict['peers']
    decimal_values = [byte for byte in peers]
    
    ip_address_list = []
    for i in range(0,len(decimal_values),6):
        ip_address = '.'.join(str(num) for num in decimal_values[i:i+4])
        ip_address += f":{int.from_bytes(decimal_values[i+4:i+6], byteorder='big', signed=False)}"
        ip_address_list.append(ip_address)
     
    return ip_address_list
def get_peer_address_magnet(url, sha_info_hash):  
    encoded_hash = url_encode(sha_info_hash)
    peer_id = '3a5f9c1e2d4a8e3b0f6c'
    port = 6881
    uploaded = 0
    downloaded = 0
    left = 999
    compact = 1
    
    query_string = (
        f"info_hash={encoded_hash}&"
        f"peer_id={peer_id}&"
        f"port={port}&"
        f"uploaded={uploaded}&"
        f"downloaded={downloaded}&"
        f"left={left}&"
        f"compact={compact}"
    )
    
    complete_url = f"{url}?{query_string}"
    r = requests.get(complete_url)
    decoded_dict,_ = decode_bencode(r.content)
    peers = decoded_dict['peers']
    decimal_values = [byte for byte in peers]
    
    ip_address_list = []
    for i in range(0,len(decimal_values),6):
        ip_address = '.'.join(str(num) for num in decimal_values[i:i+4])
        ip_address += f":{int.from_bytes(decimal_values[i+4:i+6], byteorder='big', signed=False)}"
        ip_address_list.append(ip_address)
     
    return ip_address_list     
def receive_large_data(s,size):
    result_data = b''
    curr_size = 0
    
    while curr_size < size:
        data_size_to_receive = min(4096,size-curr_size)
        temp_data = s.recv(data_size_to_receive)
        curr_size += len(temp_data)
        result_data += temp_data
    return result_data
def integer_to_byte(integer):
    return struct.pack('>I', integer)
def byte_to_integer(byte):
    return struct.unpack('>I', byte)[0]
def send_data(s,piece_offset,block_offset,data_length):
    s.sendall(b'\x00\x00\x00\x0d')
    s.sendall(b'\x06')
    s.sendall(integer_to_byte(piece_offset))
    s.sendall(integer_to_byte(block_offset))
    s.sendall(integer_to_byte(data_length))
    
def receive_data(s):
    payload_size = byte_to_integer(s.recv(4))
    s.recv(1)
    s.recv(4)
    s.recv(4)
    return receive_large_data(s,payload_size-9)
def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        
        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")
        
        decoded_value,_ = decode_bencode(bencoded_value)
        print(json.dumps(decoded_value, default=bytes_to_str))
    
    elif command == 'info':
        bencoded_file = sys.argv[2]
        
        decoded_value = get_decoded_value(bencoded_file)
        url = announce_url(decoded_value)
        info_dict = get_info_dict(decoded_value)
        sha_info_hash = get_sha_info(info_dict)
        
        pieces = info_dict['pieces']
        hex_string = pieces.hex()
        
        print(f'Tracker URL: {url}')
        print(f'Length: {info_dict["length"]}')
        print(f'Info Hash: {sha_info_hash}')
        print(f'Piece Length: {info_dict["piece length"]}')
        print('Piece Hashes:')
        for i in range(0,len(hex_string),40):
            print(hex_string[i:i+40])
            
    elif command == 'peers':
        bencoded_file = sys.argv[2]
        
        ip_address_list = get_peer_address_torrent(bencoded_file)
        for ip_address in ip_address_list:
            print(ip_address)
            
    elif command == 'handshake':
        bencoded_file = sys.argv[2]
        peer_details = sys.argv[3]
        
        peer_ip, peer_port = peer_details.split(':')
        peer_port = int(peer_port)
        
        decoded_value = get_decoded_value(bencoded_file)
        url = announce_url(decoded_value)
        info_dict = get_info_dict(decoded_value)
        sha_info_hash = get_sha_info(info_dict)
        
        peer_id = '3a5f9c1e2d4a8e3b0f6c'
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        response_peer_id = ping_peer_torrent(peer_ip,peer_port,sha_info_hash,peer_id, s)
        print(f'Peer ID: {response_peer_id}')
        
    elif command == 'download_piece':
        download_location = sys.argv[3] 
        torrent_file = sys.argv[4]
        piece = int(sys.argv[5])
        
        decoded_value = get_decoded_value(torrent_file)
        url = announce_url(decoded_value)
        info_dict = get_info_dict(decoded_value)
        sha_info_hash = get_sha_info(info_dict)
        
        ip_addresses = get_peer_address_torrent(torrent_file)
        peer_ip, peer_port = ip_addresses[0].split(':')
        peer_port = int(peer_port)
        
        peer_id = '3a5f9c1e2d4a8e3b0f6c'
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        response_peer_id = ping_peer_torrent(peer_ip,peer_port,sha_info_hash,peer_id, s)
        
        total_length = info_dict['length']
        piece_length = info_dict['piece length']
        piece_length = min(piece_length,total_length - piece*piece_length)
        
        # Bitfield
        s.recv(4)
        s.recv(1)
        s.recv(4)
        
        # Interested
        s.sendall(b'\x00\x00\x00\x01')
        s.sendall(b'\x02')
        # Unchoke
        s.recv(4)
        s.recv(1)
        
        block_size = 2**14
        curr_sent_data_size = 0
        iterations = 0
        
        while curr_sent_data_size < piece_length:
            data_size_to_send = min(block_size,piece_length-curr_sent_data_size)
            curr_sent_data_size += data_size_to_send
            send_data(s,piece,iterations*block_size,data_size_to_send)
            iterations += 1
        
        result_data = b''
        for i in range(0,iterations):
            result_data += receive_data(s)
        
        with open(download_location, "wb") as f:  # Use "wb" for binary write mode
            f.write(result_data)  # No need to decode
            
    elif command=='download':
        download_location = sys.argv[3] 
        torrent_file = sys.argv[4]
        
        decoded_value = get_decoded_value(torrent_file)
        url = announce_url(decoded_value)
        info_dict = get_info_dict(decoded_value)
        sha_info_hash = get_sha_info(info_dict)
        
        ip_addresses = get_peer_address_torrent(torrent_file)
        peer_ip, peer_port = ip_addresses[0].split(':')
        peer_port = int(peer_port)
        
        peer_id = '3a5f9c1e2d4a8e3b0f6c'
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        response_peer_id = ping_peer_torrent(peer_ip,peer_port,sha_info_hash,peer_id, s)
        
        total_length = info_dict['length']
        piece_length = info_dict['piece length']
        
        # Bitfield
        s.recv(4)
        s.recv(1)
        s.recv(4)
        
        # Interested
        s.sendall(b'\x00\x00\x00\x01')
        s.sendall(b'\x02')
        # Unchoke
        s.recv(4)
        s.recv(1)
        
        for i in range(0,total_length,piece_length):
            curr_piece_length = min(piece_length,total_length-i)
            block_size = 2**14
            curr_sent_data_size = 0
            iterations = 0
            
            while curr_sent_data_size < curr_piece_length:
                data_size_to_send = min(block_size,curr_piece_length-curr_sent_data_size)
                curr_sent_data_size += data_size_to_send
                send_data(s,i//piece_length,iterations*block_size,data_size_to_send)
                iterations += 1
        
            result_data = b''
            for i in range(0,iterations):
                result_data += receive_data(s)
            
            with open(download_location, "ab") as f:
                f.write(result_data)
                
    elif command == 'magnet_parse':
        magnet_link = sys.argv[2]
        info_hash_location = magnet_link.find('btih:') + 5
        info_hash = magnet_link[info_hash_location:info_hash_location+40]
        url_location = magnet_link.find('tr=') + 3
        url = magnet_link[url_location:]
        print(f'Tracker URL: {urllib.parse.unquote(url)}') 
        print(f'Info Hash: {info_hash}')  
          
    elif command == 'magnet_handshake':
        magnet_link = sys.argv[2]  
        info_hash_location = magnet_link.find('btih:') + 5
        info_hash = magnet_link[info_hash_location:info_hash_location+40]
        url_location = magnet_link.find('tr=') + 3
        url = magnet_link[url_location:]  
        url = urllib.parse.unquote(url)
        ip_addresses = get_peer_address_magnet(url,info_hash)
        peer_ip, peer_port = ip_addresses[0].split(':')
        peer_port = int(peer_port)
        
        peer_id = '3a5f9c1e2d4a8e3b0f6c'
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        response_peer_id = ping_peer_magnet(peer_ip,peer_port,info_hash,peer_id, s)
        print(f'Peer ID: {response_peer_id}')
        
        # Bitfield
        s.recv(4)
        s.recv(1)
        s.recv(4)
        
        magnet_dict = {"m": {
            "ut_metadata": 18
        }}
        
        encoded_magnet_dict = bencodepy.encode(magnet_dict)
        s.sendall(integer_to_byte(len(encoded_magnet_dict) + 2))
        s.sendall(b'\x14')
        s.sendall(b'\x00')
        s.sendall(encoded_magnet_dict)
        
        payload_size = byte_to_integer(s.recv(4)) - 2
        s.recv(1)
        s.recv(1)
        handshake_message = s.recv(payload_size)
        handshake_message = decode_bencode(handshake_message)
        print(f'Peer Metadata Extension ID: {handshake_message[0]['m']['ut_metadata']}')
    
    elif command == 'magnet_info':
        magnet_link = sys.argv[2]
        info_hash_location = magnet_link.find('btih:') + 5
        info_hash = magnet_link[info_hash_location:info_hash_location+40]
        url_location = magnet_link.find('tr=') + 3
        url = magnet_link[url_location:]  
        url = urllib.parse.unquote(url)
        ip_addresses = get_peer_address_magnet(url,info_hash)
        peer_ip, peer_port = ip_addresses[0].split(':')
        peer_port = int(peer_port)
        
        peer_id = '3a5f9c1e2d4a8e3b0f6c'
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        response_peer_id = ping_peer_magnet(peer_ip,peer_port,info_hash,peer_id, s)
        
        s.recv(4)
        s.recv(1)
        s.recv(4)
        
        magnet_dict = {"m": {
            "ut_metadata": 18
        }}
        
        encoded_magnet_dict = bencodepy.encode(magnet_dict)
        s.sendall(integer_to_byte(len(encoded_magnet_dict) + 2))
        s.sendall(b'\x14')
        s.sendall(b'\x00')
        s.sendall(encoded_magnet_dict)
        
        payload_size = byte_to_integer(s.recv(4)) - 2
        s.recv(1)
        s.recv(1)
        handshake_message = s.recv(payload_size)
        
        request_metadata = {
            'msg_type': 0,
            'piece': 0
        }
        
        request_metadata = bencodepy.encode(request_metadata)
        s.sendall(integer_to_byte(len(request_metadata) + 2))
        s.sendall(b'\x14')
        s.sendall(b'\x00')
        s.sendall(request_metadata)

        payload_size = byte_to_integer(s.recv(4)) - 2
        s.recv(1)
        s.recv(1)
        handshake_message = decode_bencode(s.recv(payload_size))
        handshake_info_dict = decode_bencode(handshake_message[1])[0]
        print(f'Tracker URL: {url}')   
        print(f'Length: {handshake_info_dict['length']}')
        print(f'Info Hash: {info_hash}')
        print(f'Piece Length: {handshake_info_dict['piece length']}')
        print(f'Piece Hashes:')
        piece_hashes = handshake_info_dict['pieces'].hex()
        print(piece_hashes)
               
    else:
        raise NotImplementedError(f"Unknown command {command}") 




'''
def decode_part(value, start_index):
    if chr(value[start_index]).isdigit():
        return decode_string(value, start_index)
    elif chr(value[start_index]) == "i":
        return decode_integer(value, start_index)
    elif chr(value[start_index]) == "l":
        return decode_list(value, start_index)
    elif chr(value[start_index]) == "d":
        return decode_dict(value, start_index)
    else:
        raise NotImplementedError(
            "Only strings and integers are supported at the moment"
        )
def decode_string(bencoded_value, start_index):
    if not chr(bencoded_value[start_index]).isdigit():
        raise ValueError("Invalid encoded string", bencoded_value, start_index)
    bencoded_value = bencoded_value[start_index:]
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    length = int(bencoded_value[:first_colon_index])
    word_start = first_colon_index + 1
    word_end = first_colon_index + length + 1
    return bencoded_value[word_start:word_end], start_index + word_end
def decode_integer(bencoded_value, start_index):
    if chr(bencoded_value[start_index]) != "i":
        raise ValueError("Invalid encoded integer", bencoded_value, start_index)
    bencoded_value = bencoded_value[start_index:]
    end_marker = bencoded_value.find(b"e")
    if end_marker == -1:
        raise ValueError("Invalid encoded integer", bencoded_value)
    return int(bencoded_value[1:end_marker]), start_index + end_marker + 1
def decode_list(bencoded_value, start_index):
    if chr(bencoded_value[start_index]) != "l":
        raise ValueError("Invalid encoded list", bencoded_value, start_index)
    current_index = start_index + 1
    values = []
    while chr(bencoded_value[current_index]) != "e":
        value, current_index = decode_part(bencoded_value, current_index)
        values.append(value)
    return values, current_index + 1
def decode_dict(bencoded_value, start_index):
    if chr(bencoded_value[start_index]) != "d":
        raise ValueError("Invalid encoded dict", bencoded_value, start_index)
    current_index = start_index + 1
    values = {}
    while chr(bencoded_value[current_index]) != "e":
        key, current_index = decode_string(bencoded_value, current_index)
        value, current_index = decode_part(bencoded_value, current_index)
        values[key.decode()] = value
    return values, current_index
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    return decode_part(bencoded_value, 0)[0]
def encode_string(value):
    length = len(value)
    return f"{length}:{value}"
def encode_int(value):
    return f"i{value}e"
def encode_bencode(value):
    final_string = ""
    if(type(value)==dict):
        final_string = "d"
        
        for key in list(value.keys()):
            print(key)
            key_string = encode_string(key) 
            dict_value = encode_bencode(value[key])
            final_string+=key_string+dict_value
        final_string+="e"
    elif(type(value)==list):
        final_string = "l"
        for i in value:
            if(type(i)==str):
                final_string+=encode_string(i)
            elif(type(i)==int):
                final_string+=encode_int(i)
    
        final_string+="e"
    elif(type(value)==str):
        final_string+=encode_string(value)
    elif(type(value)==int):
        final_string+=encode_int(value)
    return  final_string
def download_piece(decoded,hashed_info,piece_index,outputfile):
    peers = get_peers(hashed_info,decoded)
    peer_index = random.randint(0,len(peers))
    # print(peers)
    # print(peer_index)
    try:
        peer_id_name = get_peer_id(peers[peer_index][0],peers[peer_index][1],hashed_info)
    except IndexError:
        #print('again this stupid error for piece ',piece_index)
        return download_piece(decoded,hashed_info,piece_index,outputfile)
    print(f"{piece_index} is downloaded from {peer_id_name}")
    # print("Stage1 for ",piece_index)
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client:
        
        client.connect((peers[peer_index][0],peers[peer_index][1]))
        #print("Stage 1 for ",piece_index,peer_id_name)
        client.send(
            b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
                + hashed_info
                + "abcdefghijklmnoptest".encode()
        )
        #print("Stage 1.1 for ",piece_index,peer_id_name)
        response = client.recv(68)
        #print("Stage 1.2 for ",piece_index,peer_id_name)
        # print(response[48:].hex())
        message = get_message(client)
        if(message==False):
            return download_piece(decoded,hashed_info,piece_index,outputfile)
        #print("Stage 2 for ",piece_index,peer_id_name)
        #print("message is received for", piece_index)
        # print(message.hex())
        while int(message[4]) != 5:
            message = get_message(client)
            #print('checking for interested',peer_index)
        value1 = 1
        value2 = 2
        # print(message.hex())
        interested_payload = (
            (value1 >> 24 & 0xFF).to_bytes(1, 'big') +  # First byte (most significant)
            (value1 >> 16 & 0xFF).to_bytes(1, 'big') +  # Second byte
            (value1 >> 8 & 0xFF).to_bytes(1, 'big') +   # Third byte
            (value1 & 0xFF).to_bytes(1, 'big') +        # Fourth byte (least significant)
            value2.to_bytes(1, 'big')                   # Single byte
        )
        client.sendall(interested_payload)
        
        message = get_message(client)
        if(message==False):
            return download_piece(decoded,hashed_info,piece_index,outputfile)
        # print(message.hex())
        print("Stage3 for ",piece_index,peer_id_name)
        while int(message[4]) != 1:
            message = get_message(client)
            #print('checking for unchoked',peer_index)
        # print(message.hex())
        # print("\n\nStage4 for ",piece_index)
        print('stage 4',piece_index,peer_id_name)
        total_number_of_pieces = len(
            extract_pieces_hashes(decoded[b"info"][b"pieces"])
        )
        file_length = decoded[b"info"][b"length"]
        default_piece_length = decoded[b"info"][b"piece length"]
        if piece_index == total_number_of_pieces - 1:
            piece_length = file_length - (default_piece_length * piece_index)
        else:
            piece_length = default_piece_length
        
        number_of_blocks = math.ceil(piece_length / (16 * 1024))
        data= bytearray()
        print('stage 5',piece_index,peer_id_name)
        for block_index in range(number_of_blocks):
            # print('\n\n\n\n\nstuck here',piece_index)
            begin = 2**14 * block_index
            # print(f"begin: {begin}")
            block_length = min(piece_length - begin, 2**14)
            # print(
            #     f"Requesting block {block_index + 1} of {number_of_blocks} with length {block_length}"
            # )
            request_payload = struct.pack(
                ">IBIII", 13, 6, piece_index, begin, block_length
            )
            # print("Requesting block, with payload:")
            # print(request_payload)
            # print(struct.unpack(">IBIII", request_payload))
            # print(int.from_bytes(request_payload[:4]))
            # print(int.from_bytes(request_payload[4:5]))
            # print(int.from_bytes(request_payload[5:9]))
            # print(int.from_bytes(request_payload[17:21]))
            client.sendall(request_payload)
            message = get_message(client)
            # print(message)
            data.extend(message[13:])
        print('stage 6',piece_index,peer_id_name)
        with open(outputfile, "wb") as f:
            f.write(data)
        client.close()
    return outputfile
def get_peer_id(ip,port,info_hash):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((ip, port))
            client.send(
                b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
                + info_hash
                + "abcdefghijklmnoptest".encode()
            )
            reply = client.recv(68)
    return reply[48:].hex()
def extract_pieces_hashes(pieces):
    pieces_list = []
    for i in range(0,len(pieces),20):
        pieces_list.append(pieces[i:i+20].hex())
    return pieces_list
def get_peers(info_hash,decoded):
    try:
        response = requests.get(decoded[b'announce'].decode(),params={
                'info_hash':info_hash,
                'peer_id':'abcdefghijklmnoptest',
                'port':6851,
                'uploaded':0,
                'downloaded':0,
                'left':decoded[b'info'][b'length'],
                'compact':1
            })
    except KeyError:
        response = requests.get(decoded['announce'],params={
                'info_hash':info_hash,
                'peer_id':'abcdefghijklmnoptest',
                'port':6851,
                'uploaded':0,
                'downloaded':0,
                'left':decoded['info']['length'],
                'compact':1
            })
    decoded_response = bencodepy.decode(response.content)
    peer_list = []
    for i in range(0,len(decoded_response[b'peers']),6):
        peer = decoded_response[b'peers'][i : i + 6]
        ip_address = f"{peer[0]}.{peer[1]}.{peer[2]}.{peer[3]}"
        port = int.from_bytes(peer[4:],byteorder='big')
        peer_list.append((ip_address,port))
    return peer_list
def get_message(s):
    length = s.recv(4)
    while not length or not int.from_bytes(length):
        return False
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))
    while len(message) < int.from_bytes(length):
        #print("NOOOOO HEREEEEEEE")
        message += s.recv(int.from_bytes(length) - len(message))
    return length + message
            
def decode_torrentfile(filename):
    with open(filename,'rb') as f:
        torrent = f.read()
        decoded = bencodepy.decode(torrent)
    return decoded
def download(outputfile, filename):
    decoded_value = decode_torrentfile(filename)
    total_pieces = len(extract_pieces_hashes(decoded_value[b"info"][b"pieces"]))
    piecefiles = []
    threads = []
    #print('Total number of pieces: ',total_pieces)
    for piece in range(0, total_pieces):
        info = bencodepy.encode(decoded_value[b'info'])
        encoded_info = info
        hashed_info = hashlib.sha1(encoded_info)
        out =  "test-" + str(piece)
        t = threading.Thread(target=download_piece,args=(decoded_value,hashed_info.digest(), piece, out))
        threads.append(t)       
        t.start()
        piecefiles.append(out)
    #print('\n\n\n\n\n\nthreads are running\n\n\n\n\n\n')
    for t in range(0,len(threads)):
        threads[t].join()
        # print(f'{t}th thread is doneh')
    
    #print('\n\n\n\n\n\nthreads are joined\n\n\n\n\n\n')
    
    with open(outputfile, "wb") as result_file:
        for piecefile in piecefiles:
            with open(piecefile, "rb") as piece_file:
                result_file.write(piece_file.read())
            os.remove(piecefile)
def magnet_parser(link):
    params = link.split('?')[1].split('&')
    params_dict = {}
    for i in params:
        paramter = i.split('=')
        params_dict[paramter[0]] = paramter[1]
    return params_dict

def magnet_handshake(ip,port,digest,ext_byte):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((ip, port))
        client.send(
            b"\x13BitTorrent protocol"+ext_byte
            + digest
                + "abcdefghijklmnoptest".encode()
        )
        reply = client.recv(68)
        peer_id = reply[48:]
        ext_support = reply[25] == b"\x10"
        print('x',reply[20:28])
        received = False
        while not received:
            length = client.recv(4)
            print(int.from_bytes(length))
            message = client.recv(int.from_bytes(length))
            handshaketype = message[0]
            print(handshaketype)
            print(message)
            if handshaketype == 5:
                while len(message) < int.from_bytes(length):
                    message += client.recv(int.from_bytes(length) - len(message))
                received = True
        print(message)
        print(ext_support)
        if ext_support:
        #  EXTENSION HANDSHAKE
            received = False
            ext_id = 0
            while not received:
                length = client.recv(4)
                if length and int.from_bytes(length):
                    extension = client.recv(int.from_bytes(length))
                    print(f"Received {int.from_bytes(length)} bytes")
                    type = extension[0]
                    print(extension)
                    if type == 20:
                        print("<<< EXTENSION HANDSHAKE")
                        # print(extension[2:])
                        payload = bencodepy.decode(extension[2:])
                        # print(payload)
                        if b"m" in payload:
                            if b"ut_metadata" in payload[b"m"]:
                                print("Extension id:", payload[b"m"][b"ut_metadata"])
                                ext_id = payload[b"m"][b"ut_metadata"]
                                received = True
        payload = {}
        payload["m"] = {}
        payload["m"]["ut_metadata"] = 16
        enc_payload = bencodepy.encode(payload)
        print(enc_payload)
        packet_header = int(len(enc_payload) + 1 + 1).to_bytes(4)
        
        packet = packet_header + b"\x14\x00" + enc_payload
        client.sendall(packet)
        length = client.recv(4)
        print(int.from_bytes(length))
        message = client.recv(int.from_bytes(length))
        while len(message) < int.from_bytes(length):
            message += client.recv(int.from_bytes(length) - len(message))
        print(message)
        decoded = bencodepy.decode(message[2:])
    return peer_id.hex(),ext_support,decoded[b"m"][b"ut_metadata"]

def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == 'info':
        file_name = sys.argv[2]
        with open(file_name,'rb') as f:
            torrent = f.read()
        decoded = bencodepy.decode(torrent)
        info = bencodepy.encode(decoded[b'info'])
        encoded_info = info
        hashed_info = hashlib.sha1(encoded_info)
        print(f"Tracker URL: {decoded[b'announce'].decode()}")
        print(f"Length: {decoded[b'info'][b'length']}")
        # print(hashlib.sha1(encode_bencode(decoded['info']).encode()).hexdigest())
        print(f"Info Hash: {hashed_info.hexdigest()}")
        print(f'Piece Length: {decoded[b'info'][b"piece length"]}')
        print(f"Piece Hashes: ")
        for i in range(0,len(decoded[b'info'][b"pieces"]),20):
            print(decoded[b'info'][b'pieces'][i:i+20].hex())
    elif command == 'peers':
        file_name = sys.argv[2]
        with open(file_name,'rb') as f:
            torrent = f.read()
        decoded = bencodepy.decode(torrent)
        info = bencodepy.encode(decoded[b'info'])
        encoded_info = info
        hashed_info = hashlib.sha1(encoded_info)
        response = requests.get(decoded[b'announce'].decode(),params={
            'info_hash':hashed_info.digest(),
            'peer_id':'abcdefghijklmnoptest',
            'port':3000,
            'uploaded':0,
            'downloaded':0,
            'left':decoded[b'info'][b'length'],
            'compact':1
        })
        decoded_response = bencodepy.decode(response.content)
        for i in range(0,len(decoded_response[b'peers']),6):
            peer = decoded_response[b'peers'][i : i + 6]
            ip_address = f"{peer[0]}.{peer[1]}.{peer[2]}.{peer[3]}"
            port = int.from_bytes(peer[4:],byteorder='big')
            print(f"{ip_address}:{port}")
        
    elif command == 'handshake':
        file_name = sys.argv[2]
        (ip,port) = sys.argv[3].split(':')
        with open(file_name,'rb') as f:
            torrent = f.read()
            decoded = bencodepy.decode(torrent)
            info = bencodepy.encode(decoded[b'info'])
            encoded_info = info
            hashed_info = hashlib.sha1(encoded_info)
            addr = sys.argv[3].split(":")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((addr[0], int(addr[1])))
            client.send(
                b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
                + hashed_info.digest()
                + "abcdefghijklmnoptest".encode()
            )
            reply = client.recv(68)
        print("Peer ID:", reply[48:].hex())
    elif command == 'download_piece':
        output_file = sys.argv[3]
        torrent_file = sys.argv[4]
        piece_index = int(sys.argv[5])
        with open(torrent_file, "rb") as f:
            torrent_data = f.read()
        decoded = bencodepy.decode(torrent_data)
        info = bencodepy.encode(decoded[b'info'])
        encoded_info = info
        hashed_info = hashlib.sha1(encoded_info)
        if download_piece(
                decoded,
                hashed_info.digest(),
                piece_index,
                output_file,
            ):
            print(f"Piece {piece_index} downloaded to {output_file}.")
        else:
            raise RuntimeError("Failed to download piece")
           
    elif command == 'download':
        outputfile = sys.argv[3]
        filename = sys.argv[4]
        download(outputfile, filename)
        print("Download %s to %s" % (filename, outputfile))
    elif command == "magnet_parse":
        magnet_url = sys.argv[2]
        parsed =  magnet_parser(magnet_url)
        print("Tracker URL:",urllib.parse.unquote(parsed['tr']))
        print("Info Hash:",parsed['xt'].split(':')[-1])
    elif command == "magnet_handshake":
        magnet_url = sys.argv[2]
        parsed =  magnet_parser(magnet_url)
        tracker = urllib.parse.unquote(parsed['tr'])
        hexdigest = parsed['xt'].split(':')[-1]
        digest = bytes.fromhex(hexdigest)
        data = {}
        data["announce"] = tracker
        data["info"] = {}
        data["info"]["length"] = 1024
        peers_list = get_peers(digest, data)
        peer_id,ext_support, extend_handshake_id = magnet_handshake(peers_list[0][0],peers_list[0][1],digest,int(0x100000).to_bytes(8))
        print("Peer ID:",peer_id)
        print("Peer Metadata Extension ID:",extend_handshake_id)
        if ext_support:
            print("Peer supports extensions")
    else:
        raise NotImplementedError(f"Unknown command {command}")'''

if __name__ == "__main__":
    main()
