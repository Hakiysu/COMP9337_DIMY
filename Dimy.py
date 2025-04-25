# Dimy.py
import argparse
import hashlib
import json
import os
import random
import socket
import sys
import threading
import time
import uuid
from collections import defaultdict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from subrosa import split_secret, recover_secret, Share

from GLOBAL_DEFINE import BF_SIZE
from bloom_filter import BloomFilter

class Node:
    def __init__(self, t, k, n, server_ip, server_port):
        # node basic info
        self.node_uuid = str(uuid.uuid4())[:8]
        self.t = t
        self.k = k
        self.n = n
        self.server_ip = server_ip
        self.server_port = server_port

        # node key
        # Task 5, read DH parameters from file
        with open("dh_params.pem", "rb") as f:
            param_bytes = f.read()
            self.parameters = serialization.load_pem_parameters(param_bytes)
        # though pem is same, but it can generate different key pair
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

        # DBF: daily bloom filter, save all encid in t*6 seconds
        # maximum for each node are 6 DBFs
        # if over Dt, the oldest DBF will be deleted
        # Dt= (t*6*6)/60 minutes
        self.dbf = BloomFilter()
        self.dbf_list = []
        self.dbf_add_counter = 0
        self.current_dbf = None

        # QBF: query bloom filter
        # during Dt, all DBFs will be merged into QBF
        self.qbf = BloomFilter()
        self.qbf_enabled = True
        self.infected = False  # infected node flag

        # CBF: contact bloom filter
        # infected node can upload CBF to server. once uploaded, the QBF generation will stop.
        # node will receive server response(SUCCESS or FAIL)
        self.cbf = BloomFilter()

        self.dbf_duration = 6  # period of saving DBF
        self.Dt = t * 6 * 6  # QBF update interval, in assignment, it shows as minutes, but in code it is seconds, so ignore "/60"

        self.received_shares = defaultdict(list)

        # UDP socket for listening
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.listen_sock.bind(("", self.server_port))
        print(f"[{self.node_uuid}] Listening on port {self.server_port}...")

        # UDP socket for sending
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Task 3, broadcast via UDP
        self.send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def generate_public_key(self):
        public_key = self.private_key.public_key()
        return public_key

    # Task 5
    def generate_enc_id(self, remote_public_key):
        # Task 5, generate EncID by use DH key exchange.
        # use self private key and remote public key
        shared_secret = self.private_key.exchange(remote_public_key)
        enc_id = hashlib.sha256(shared_secret).digest()
        print(f"[{self.node_uuid}] Generated Encounter ID: {enc_id.hex()}")
        return enc_id

    # Task 7
    def update_dbf_list(self):
        while True: # its a loop
            time.sleep(self.t * 6)  # task 7 time interval for one DBF save all encid within t*6 seconds
            # sleep first, then update or create new DBF
            print(f"[{self.node_uuid}] [Task 7-B] Updating DBF list, waiting for {self.t * 6} seconds...")
            now = time.time()
            # here are two limit of dbf: time expire, num limit
            # 1. if time is over Dt, delete it
            # 2. if num is over 6 ( will be 7), delete the oldest one

            # delete expired DBF
            cutoff_time = now - self.Dt
            before = len(self.dbf_list)
            self.dbf_list = [(timestamp, dbf) for timestamp, dbf in self.dbf_list if
                             timestamp > cutoff_time]  # Task 7: filter out expired DBFs, renew the list
            after = len(self.dbf_list)
            print(f"[{self.node_uuid}] Time expire: {bool(before != after)}.")
            if before != after:
                print(f"[{self.node_uuid}] Clean expire DBF：from {before} to {after}")

            # create new DBF
            # when come here, already have a DBF when in reconstruct func
            print(f"[{self.node_uuid}] Create new DBF.")
            self.current_dbf = BloomFilter(size=BF_SIZE, hash_count=3) # new a DBF
            # add current DBF to DBF list
            self.current_dbf.bit_array |= self.dbf.bit_array # merge the current DBF with the previous DBF

            # add current DBF to DBF list
            self.dbf_list.append((now, self.current_dbf))
            print(f"[{self.node_uuid}] Created new DBF，now total {len(self.dbf_list)}  DBF。")
            # delete/limit DBF list to 6, if number of DBF exceeds 6, remove the oldest one
            if len(self.dbf_list) > 6:
                self.dbf_list = self.dbf_list[-6:]
                print(f"[{self.node_uuid}] [Task 7-B] DBF list size exceeded 6, trimming to {len(self.dbf_list)}.")
            # Attention, imagine now is already have 6 DBF,
            #   then create a new one, so total 7 DBF,
            #   then the oldest one will be deleted here.
            #   DBF num will be 6 finally.

    def generate_qbf(self):
        # if DBF list is empty, return
        if not self.dbf_list:
            return

        print(f"[{self.node_uuid}] [Task 8] Generating QBF...")
        # initialize a new Bloom Filter as QBF
        qbf = BloomFilter(size=BF_SIZE, hash_count=3)

        # copy the bit array from the first DBF
        qbf.bit_array = self.dbf_list[0][1].bit_array.copy()

        # merge the remaining DBFs (bitwise OR)
        for _, dbf in self.dbf_list[1:]:
            qbf.bit_array |= dbf.bit_array

        self.qbf = qbf
        print(f"[{self.node_uuid}] generate QBF complete，merge total {len(self.dbf_list)}  DBF。")

    def generate_cbf(self):
        # only contain infected node self
        if not self.dbf_list:
            print("No DBF to combine into CBF.")
            return
        print(f"[{self.node_uuid}] [Task 9] Generating CBF...")
        self.infected = True
        # initialize a new Bloom Filter as CBF
        cbf = BloomFilter(size=BF_SIZE, hash_count=3)
        # add node self info to CBF
        print(f"[{self.node_uuid}] [Task 9] Starting to combine DBF into CBF...")
        for _, dbf in self.dbf_list:
            # merge the remaining DBFs (bitwise OR)
            cbf.bit_array |= dbf.bit_array
        self.cbf = cbf
        print(f"[{self.node_uuid}] Generate CBF complete，merge total {len(self.dbf_list)} DBFs。")

    # Task 9
    def upload_cbf_to_server(self):
        # if node self isn't infected, no need to upload CBF
        if not self.cbf:
            print("No CBF to upload.")
            return
        # if infected node, upload CBF to server, it will execute only once

        # cbf serialization
        cbf_serialized = self.cbf.serialize()
        cbf_data = {
            "type": "CBF",
            "node_id": self.node_uuid,
            "bloom_filter": cbf_serialized
        }

        # upload CBF to server via TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"[{self.node_uuid}] [Task 9] Connect to server ===> {self.server_ip}:{self.server_port}...")
            s.connect(("127.0.0.1", self.server_port))
            print(f"[{self.node_uuid}] [Task 9] Sending CBF now...")
            s.sendall(json.dumps(cbf_data).encode('utf-8'))
            s.shutdown(socket.SHUT_WR)  # send EOF to server
            # wait for server response
            response = s.recv(1024).decode('utf-8')
            s.close()
            print(f"[{self.node_uuid}] Server response received.")

            if response == "SUCCESS":
                print(f"[{self.node_uuid}] CBF Uploaded successfully, stopping QBF generation.")
                self.stop_qbf_generation()  # Task 9, once CBF uploaded, stop QBF generation

    def stop_qbf_generation(self):
        self.qbf_enabled = False
        print(f"[{self.node_uuid}] Stop QBF generation.")

    def simulate_positive(self):# Task 11-b
        while True:
            time.sleep(0.5)
            # Simulate a positive case
            print(f"[{self.node_uuid}] Simulating positive case...")
            self.infected = True
            self.generate_cbf()
            self.upload_cbf_to_server()
            self.qbf_enabled = True  # keep QBF generation enabled

    # Task 3
    def generate_and_broadcast_loop(self):
        while True:
            pubkey = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode() # Task 11, broadcast self public key to all nodes
            ephid = os.urandom(32)  # Task 1, generate random EphID
            ephid_hash = hashlib.sha256(ephid).hexdigest()
            print(f"[{self.node_uuid}] [Task 1] Generated EphID: {ephid.hex()}, hash: {ephid_hash}")
            # split into n shares with threshold k
            shares = split_secret(ephid, self.k, self.n)  # Task 2, use k-out-of-n Shamir secret sharing (by subrosa)
            print(f"[{self.node_uuid}] [Task 2] Split EphID into {len(shares)} shares/chunks. k (threshold)= {self.k}, n (share_count)= {self.n}")
            for share in shares:
                # serialize share as bytes
                share_bytes = bytes(share)
                payload = json.dumps({
                    "type": "EphID",
                    "node_uuid": self.node_uuid,
                    "ephid_hash": ephid_hash,
                    "share_bytes": share_bytes.hex(),
                    "public_key": pubkey  # node will broadcast its public key to all nodes.
                    # all node will use the same public key which save in dh_params.pem locally.
                }).encode('utf-8')
                self.send_sock.sendto(payload, (self.server_ip, self.server_port))  # broadcast
                time.sleep(3)  # Task 3, interval of broadcast for one share is 3 seconds
                print(f"[{self.node_uuid}] [Task 3-A] Broadcast share x={share.x}, waiting for 3 seconds...")
            time.sleep(self.t)  # Task 1, time interval as t, to generate new EphID

    # Task 10, QBF check loop
    def qbf_check_loop(self):
        while self.qbf_enabled:
            try:
                print(f"[{self.node_uuid}] [Task 8] QBF check loop started. Interval is {self.Dt/60} minutes.")
                time.sleep(self.Dt)  # time interval for QBF generation
                self.generate_qbf()
                # send QBF to server for checking
                qbf_serialized = self.qbf.serialize()
                qbf_data = {
                    "type": "QBF",
                    "node_id": self.node_uuid,
                    "bloom_filter": qbf_serialized
                }
                # upload QBF to server via TCP
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    print(f"[{self.node_uuid}] [Task 10-A] Connect to server ===> {self.server_ip}:{self.server_port}...")
                    s.connect(("127.0.0.1", self.server_port))
                    print(f"[{self.node_uuid}] Uploading QBF to server...")
                    s.sendall(json.dumps(qbf_data).encode('utf-8'))
                    s.shutdown(socket.SHUT_WR)
                    # wait for server response
                    print(f"[{self.node_uuid}] Waiting for server response...")
                    response = s.recv(1024).decode('utf-8')
                    print(f"[{self.node_uuid}] [Task 10-B] Response from server: {response}")
                    s.close()
                    print(f"[{self.node_uuid}] Server response received.")
                    # check server response
                    response_data = json.loads(response)
                    matched = response_data.get("matched", False)
                    if matched:
                        print(f"[{self.node_uuid}] QBF matched with CBF list in server! Infected node detected.")
                        self.infected = True
                        # Task 9, once QBF matched with CBF, upload CBF to server
                        self.generate_cbf()
                        self.upload_cbf_to_server()

                        self.stop_qbf_generation()
                        break
                    else:
                        print(f"[{self.node_uuid}] QBF not matched with CBF. No infected node detected.")
                print(f"[{self.node_uuid}] QBF check complete.")
            except Exception as e:
                print(f"[{self.node_uuid}] Exception: {e}")

    def listen_loop(self):
        while True:
            data, addr = self.listen_sock.recvfrom(4096)
            # Task 3a
            # message drop with 50% probability
            if random.random() < 0.5:
                print(f"[{self.node_uuid}] [Task 3-B] Dropped packet from {addr}")
                continue
            try:
                # receive and process message
                msg = json.loads(data.decode('utf-8'))
                sender = msg["node_uuid"]
                # drop message from self
                if sender == self.node_uuid:
                    continue
                # start processing message
                ephid_hash = msg["ephid_hash"]
                share_bytes = bytes.fromhex(msg["share_bytes"])
                peer_public_key = serialization.load_pem_public_key(msg["public_key"].encode())
                share = Share.from_bytes(share_bytes)
                # record share
                self.received_shares[ephid_hash].append(share)
                self.dbf.add(share_bytes)
                print(f"[{self.node_uuid}] [Task 3-C] Received share x={share.x} from {sender}, ephid_hash={ephid_hash}")
                # attempt reconstruction
                if len(self.received_shares[ephid_hash]) >= self.k:
                    print(f"[{self.node_uuid}] [Task 4-A] Enough shares received for ephid_hash={ephid_hash}, reconstructing EphID...")
                    self.reconstruct_ephid_and_generate_encid(ephid_hash, peer_public_key)  # Task 4, reconstruct EphID
            except Exception as e:
                print(f"[{self.node_uuid}] Error processing packet: {e}")

    def reconstruct_ephid_and_generate_encid(self, ephid_hash, peer_public_key):
        shares = self.received_shares[ephid_hash][:self.k]
        try:
            ephid = recover_secret(shares)
            computed_hash = hashlib.sha256(ephid).hexdigest()
            # Task 4, verify the hash if it matches the original EphID hash
            print(
                f"[{self.node_uuid}] [Task 4-B] Received EphID hash: {ephid_hash}, Computed EphID hash: {computed_hash}")
            print(f"[{self.node_uuid}] [Task 4-B] If same? {computed_hash == ephid_hash}")
            if computed_hash == ephid_hash:#Task 11,verify the hash if it matches the original EphID hash
                print(f"[{self.node_uuid}] Successfully reconstructed EphID: {ephid.hex()}")
                encid = self.generate_enc_id(peer_public_key)  # Task 5, generate EncID by use DH key exchange.

                # show pri and pub key
                print(f"[{self.node_uuid}] [Task 5-A] Self Public Key: {self.public_key}")
                print(f"[{self.node_uuid}] [Task 5-A] Self Private Key: {self.private_key.private_numbers()}")
                print(f"[{self.node_uuid}] [Task 5-A] Peer Public Key: {peer_public_key.public_numbers()}")
                print(
                    f"[{self.node_uuid}] [Task 5-A] Peer Private Key: Didn't broadcast, for keep secret while using Diffie-Hellman.")
                # show encid
                print(f"[{self.node_uuid}] [Task 5-B] EncID: {encid.hex()}")


                print(f"[{self.node_uuid}] [Task 6] Adding EncID to DBF...")
                self.dbf.add(encid)  # Task 6, add EncID to DBF
                self.dbf_add_counter += 1
                # show add which EncID in a same dbf
                print(f"[{self.node_uuid}] [Task 7-A] No. {self.dbf_add_counter} EncID added to DBF.")
                print(f"[{self.node_uuid}] [Task 7-A] DBF size: {len(self.dbf.bit_array)}")

                print(f"[{self.node_uuid}] [Task 6] Deleted EncID.")
                del encid # Task 6, delete EncID after send to DBF
            else:
                print(f"[{self.node_uuid}]  Hash mismatch! Computed {computed_hash}, expected {ephid_hash}")
        except Exception as e:
            print(f"[{self.node_uuid}] Reconstruction error: {e}")
        finally:
            # clean up
            del self.received_shares[ephid_hash]

    def start(self):
        print("Listening")
        threading.Thread(target=self.listen_loop, daemon=True).start()
        print("DBF Update")
        threading.Thread(target=self.update_dbf_list, daemon=True).start()
        print("QBF Generation and Upload")
        threading.Thread(target=self.qbf_check_loop, daemon=True).start()

        # must have a main thread to keep the program running, all threading will directly exit. so weird
        print("Broadcast")
        self.generate_and_broadcast_loop()

    def attacker_mode(self):
        threading.Thread(target=self.listen_loop, daemon=True).start()
        threading.Thread(target=self.update_dbf_list, daemon=True).start()
        threading.Thread(target=self.qbf_check_loop, daemon=True).start()
        print("ATTACK ON")
        threading.Thread(target=self.simulate_positive, daemon=True).start()
        self.generate_and_broadcast_loop()


if __name__ == "__main__":
    cli_input=sys.argv
    # turn str to acceptable value
    cli_input[1] = int(cli_input[1])
    cli_input[2] = int(cli_input[2])
    cli_input[3] = int(cli_input[3])
    cli_input[4] = str(cli_input[4])
    cli_input[5] = int(cli_input[5])

    node=Node(cli_input[1], cli_input[2], cli_input[3], cli_input[4], cli_input[5])
    node.start()


