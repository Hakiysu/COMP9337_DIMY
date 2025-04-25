# DimyServer.py
import json
import socket
import threading
from bloom_filter import BloomFilter
from GLOBAL_DEFINE import *

confirmed_cbf_list = {}


def qbf_match_cbf(qbf, cbf):
    # check if the qbf matches the cbf
    # set a threshold for the match, if > 0.5, then it is a match
    qbf_bit_array = qbf.bit_array
    cbf_bit_array = cbf.bit_array

    qbf_count = qbf_bit_array.count(qbf_bit_array)
    if qbf_count == 0:
        return False

    matched = (qbf_bit_array & cbf_bit_array).count()
    if matched / qbf_count > 0.5:
        return True
    else:
        return False

def qbf_match_cbf_fast(qbf, cbf):
    return any((qbf.bit_array & cbf.bit_array))

def handle_client(conn, addr):
    print("##################################################")
    #Task 11-c
    try:
        print(f"[SERVER] Connected to {addr}")
        # Receive the data by chunks
        data_chunks = []
        while True:
            chunk = conn.recv(1024)
            print(f"[SERVER] Received {len(chunk)} bytes from {addr}")
            if not chunk:
                break
            data_chunks.append(chunk)
        print(f"[SERVER] Received {len(chunk)} bytes from {addr} - End of transmission")
        data = b''.join(data_chunks).decode('utf-8')
        received_data = json.loads(data) # load json data

        # Deserialize the data
        node_id = received_data.get('node_id', 'Unknown')
        bf_serialized = received_data.get('bloom_filter')
        bf_type = received_data.get('type')  # CBF,QBF have special process
        bf = BloomFilter.deserialize(bf_serialized)

        # detect the type of BloomFilter
        print(f"[SERVER] Node {node_id}'s bloom filter type: {bf_type}.")
        if bf_type == 'CBF':  # Task 9
            confirmed_cbf_list.setdefault(node_id, []).append(bf)  # add the BloomFilter to the list of confirmed CBFs
            print(f"[SERVER] [Task 9] Node {node_id} sent a CBF. Add it into confirmed_cbf_list.")
            conn.send(b"SUCCESS")
            print(f"[SERVER] Response to Node {node_id}: SUCCESS")
        elif bf_type == 'QBF':  # Task 10
            print(f"[SERVER] [Task 10-C] Node {node_id} sent a QBF, start check if infected")
            # Check if the QBF matches any of the confirmed CBFs
            matched = False
            for cbf_list in confirmed_cbf_list.values():
                for cbf in cbf_list:
                    if qbf_match_cbf_fast(bf, cbf):
                        matched = True
                        break
                if matched:
                    break
            result = {'matched': matched}
            conn.send(json.dumps(result).encode('utf-8'))
            print(f"[SERVER] [Task 10-C] Response to Node {node_id}: {result}")
        else:
            print(f"[SERVER] Unknown request type from Node {node_id}")
            conn.send(b"Unknown request type.")
    except Exception as e:
        print(f"[SERVER] Error handling client {addr}: {e}")
    finally:
        conn.close()
    print("##################################################")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', SERVER_PORT))
    server.listen()
    print(f"[SERVER] Listening on {SERVER_PORT}...")
    print("==============================================")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    main()
