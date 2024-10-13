import hashlib
import json
import math
import sys
import socket
import bencodepy
import requests
def decode_bencode(bencoded_value):
    try:
        return bencodepy.Bencode(encoding="utf-8").decode(bencoded_value)
    except Exception as e:
        return bencodepy.decode(bencoded_value)
def main():
    # json.dumps() can't handle bytes, but bencoded "strings" need to be
    # bytestrings since they might contain non utf-8 characters.
    #
    # Let's convert them to strings for printing to the console.
    def bytes_to_str(data):
        if isinstance(data, bytes):
            return data.decode()
        raise TypeError(f"Type not serializable: {type(data)}")
    command = sys.argv[1]
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        # Uncomment this block to pass the first stage
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        file_name = sys.argv[2]
        with open(file_name, "rb") as file:
            parsed = decode_bencode(file.read())
            url = parsed[b"announce"].decode("utf-8")
            info = parsed[b"info"]
            length = info[b"length"]
            bencoded_info = bencodepy.encode(info)
            info_hash = hashlib.sha1(bencoded_info).hexdigest()
            piece_length = info[b"piece length"]
            pieces = info[b"pieces"]
            hashes = [
                pieces[i * 20 : i * 20 + 20].hex()
                for i in range(math.ceil(len(pieces) / 20))
            ]
            piece_hashes = "\n".join(hashes)
            output = f"""
            Tracker URL: {url}\nLength: {length}\nInfo Hash: {info_hash}\nPiece Length: {piece_length}\nPiece Hashes: \n{piece_hashes}""".strip()
            print(output)
    elif command == "peers":
        file_name = sys.argv[2]
        with open(file_name, "rb") as file:
            parsed = decode_bencode(file.read())
            url = parsed[b"announce"].decode("utf-8")
            info = parsed[b"info"]
            length = info[b"length"]
            bencoded_info = bencodepy.encode(info)
            info_hash = hashlib.sha1(bencoded_info).digest()
            response = requests.get(
                url,
                params={
                    "info_hash": info_hash,
                    "peer_id": "00112233445566778899",
                    "uploaded": 0,
                    "downloaded": 0,
                    "left": length,
                    "compact": 1,
                    "port": 6881,
                },
            )
            decoded_response = bencodepy.decode(response.content)
            raw_peers = decoded_response[b"peers"]
            peers = [parse_ip(i, raw_peers) for i in range(len(raw_peers) // 6)]
            print("\n".join(peers))
    elif command == "handshake":
        file_name = sys.argv[2]
        (ip, port) = sys.argv[3].split(":")
        with open(file_name, "rb") as file:
            parsed = decode_bencode(file.read())
            info = parsed[b"info"]
            bencoded_info = bencodepy.encode(info)
            info_hash = hashlib.sha1(bencoded_info).digest()
            handshake = (
                b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
                + info_hash
                + b"00112233445566778899"
            )
            # make request to peer
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, int(port)))
                s.send(handshake)
                print(f"Peer ID: {s.recv(68)[48:].hex()}")
    else:
        raise NotImplementedError(f"Unknown command {command}")
    
def parse_ip(i, raw_peers):
    peer = raw_peers[i * 6 : 6 * i + 6]
    ip = ".".join([str(ba) for ba in bytearray(peer[0:4])])
    port = int.from_bytes(peer[4:])
    return f"{ip}:{port}"

if __name__ == "__main__":
    main()
