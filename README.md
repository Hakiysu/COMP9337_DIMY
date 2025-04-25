# COMP9337_DIMY
UNSW 25T1 COMP9337 Final Assignment Project
## Few steps to deploy DIMY
1. Make sure your OS is base on Linux. The code cannot run on Windows due to it don't support SO_REUSEPORT. Only Linux can do.
2. Install Python >=3.9
3. Install some dependencies which show in requirements.txt, your IDE may notify you.
4. cd to project dir
5. run pem.py to generate DH parameters, you will see a file called "dh-params.pem" in same path:
       python pem.py
6. For the project, we need to open 5 terminals 
   1. In DIMY terminal: python Dimy.py 15 3 5 192.168.124.255 55000
      - Tips: python Dimy.py [time interval] [k] [n] [server_ip] [server_port]
   2. In DIMY Server terminal: python DimyServer.py
   3. In Attacker terminal: python Attacker.py
