# Attacker.py  will try to infect the network
from Dimy import Node
from GLOBAL_DEFINE import *

# Task 11
if __name__ == "__main__":
    print("[Task 11-B] Starting Attacker...")
    # reuse Node class
    # attacker is actually a node, but infected. it will keep broadcast its infected status
    attacker_node = Node(1, 3, 5, SERVER_IP_ADDR, SERVER_PORT)
    attacker_node.attacker_mode()
