# PHASE 2 — Packet Capture Layer

## Goal
Build a standalone service that sniffs live packets and outputs clean, structured events.

## Tasks
1. Write a script (`backend/capture/sniffer.py`) using Scapy's `sniff()` to capture packets on a chosen interface.
2. List available interfaces first (`scapy.all.show_interfaces()`) and let the user select one via a config value or CLI arg.
3. For each captured packet, extract: timestamp, source IP, destination IP, source port, destination port, protocol (TCP/UDP/ICMP/other), packet length.
4. Discard/ignore payload content — metadata only (per NFR3 in requirements doc).
5. Print extracted events to console first (sanity check) before wiring them anywhere else.
6. Cross-check against Wireshark running simultaneously — confirm your parsed output matches real traffic (e.g., visiting a website should show HTTP/DNS packets in both tools).
7. Wrap the sniffer in a function that accepts a callback, so later phases can plug in "what to do with each packet" without modifying this file.

## Deliverables
- `backend/capture/sniffer.py` — runnable script that prints live packet metadata to console.
- Confirmed side-by-side match against Wireshark for at least 20 packets.

## Acceptance Criteria
- [x] Script runs with admin/elevated privileges without error.
- [x] Console output shows real, correctly-parsed packets while you browse the web.
- [x] No payload/content data is captured or logged — metadata fields only.
- [x] Sniffer function accepts a callback parameter (not yet connected to anything — that's Phase 3).

## Notes
- This is the trickiest phase environment-wise (permissions, interface naming on Windows). Budget extra time here.
- If Scapy is too slow for your interface's traffic volume, note it — but don't optimize prematurely; correctness first.
