# Linux Packet Sniffer \
To run:
```bash
git clone https://github.com/sreeisme/linux-packet-sniffer.git
cd linux-packet-sniffer
gcc -o sniffer sniffer.c
sudo ./sniffer
```
Note: The default interface is set to eth0. If your system uses a different interface (e.g., enp0s3, wlan0), modify the opt variable in the source code accordingly.

