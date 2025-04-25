# raw packet

Handling level 2 packets.

```c
socket(AF_PACKET, SOCK_RAW, htons(ETH_P_WHATEVER));
```

```sh
make clean ; make && sudo ./sniffer.bin
```
