# pa2a-starter

## Info

Name: Wyatt Fong

PID: A18502576

Email: wyfong@ucsd.edu

## Description and Overview
Implemented the simple router logic in `sr_router.c`. The router now handles
incoming Ethernet frames for ARP and IP, replies to ARP requests for its own
interfaces, processes ARP replies for queued forwarded packets, responds to ICMP
echo requests sent to router interfaces, validates IP checksums, decrements TTLs,
forwards packets using exact routing-table matches, and generates ICMP errors
for TTL expiration and missing routes.

I also added extra packet-level tests in `tests/test_edge_cases.py` to exercise
router-interface pings, TTL exceeded messages, exact-route failures, ARP reply
behavior, and ARP requests on the correct outgoing link.
