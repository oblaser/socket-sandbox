https://thomasw.dev/post/packet_ignore_outgoing/ (visited 2025-04-15)

May 9, 2021

# Ignoring outgoing packets on Linux `AF_PACKET` sockets

As `AF_PACKET` sockets are used for network sniffing tools such as `tcpdump`, Wireshark, etc, by default you will get
all packets passing through the interface you bind on - incoming and outgoing packets.

For certain applications (i.e. network sensors, packet forwarders, etc) you would only be interested in incoming
(ingress) traffic. Traditionally, there are some methods to skip the outgoing (egress) packets:

1. Apply a BPF filter to the raw socket that filters on i.e. the source MAC-address. Probably the best performing
option, as the kernel filters the traffic for you prior to passing the packet to userspace.

2. You can use `recvfrom()` which fills an object of type `struct sockaddr_ll` for each message. The `sll_pkttype`
member will contain `PACKET_OUTGOING` for outgoing packets (see [packet(7)](https://man7.org/linux/man-pages/man7/packet.7.html)).
This is of course a slow option, as all packets are passed to your userspace program.

## Easier and faster..

There is, in fact, a much easier and faster option, [introduced in kernel 4.20](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fa788d986a3aac5069378ed04697bd06f83d3488).

Simply set sockopt `SOL_PACKET`, `PACKET_IGNORE_OUTGOING` to 1 and your raw socket will no longer be receiving egress
packets.

At this time, this option is not documented in any documentation or man pages and not much is written about it on the
internet, it can only be found by looking through the header files and kernel source code.

This performs much better than the BPF-filter as the packet will never enter the receive path of your socket. Using BPF
may still make sense if you want to selectively receive outgoing packets.

A program that uses BPF-filters for selectively filtering incoming packets would also benefit from enabling
`PACKET_IGNORE_OUTGOING` as the filter will not run for outgoing packets. It also allows for simplifying the filter,
increasing performance even further.
