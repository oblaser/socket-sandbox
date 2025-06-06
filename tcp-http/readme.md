# TCP HTTP

A two-fer for TCP connections and learning about HTTP.

```sh
make && ./server.bin
make && ./client.bin 127.0.0.1 8080
```

## client
usage:
```text
./client.bin IP [PORT [HTTP_HOST [HTTP_PATH]]]
```

examples:
```sh
./client.bin 127.0.0.1 8080                                             # connect to server.bin
./client.bin 193.246.105.18 80 www.msftconnecttest.com /connecttest.txt # just a tiny real life HTTP request
```
