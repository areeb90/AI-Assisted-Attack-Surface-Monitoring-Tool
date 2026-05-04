#!/bin/bash
# Nmap Scanner Script

TARGETS="10.0.1.126 10.0.1.217 10.0.1.39"   # UPDATE with your actual Target private IPs
OUTPUT_DIR="$(dirname "$0")/../data"
mkdir -p "$OUTPUT_DIR"

for TARGET in $TARGETS; do
    echo "[*] Scanning TCP: $TARGET"
    nmap -sS -p- -T4 --open -oX "$OUTPUT_DIR/scan_tcp_${TARGET}.xml" \
         -oN "$OUTPUT_DIR/scan_tcp_${TARGET}.txt" "$TARGET"

    echo "[*] Scanning UDP: $TARGET"
    nmap -sU --top-ports 20 -T4 -oX "$OUTPUT_DIR/scan_udp_${TARGET}.xml" \
         -oN "$OUTPUT_DIR/scan_udp_${TARGET}.txt" "$TARGET"
done

echo "[+] All scans complete. Files saved to $OUTPUT_DIR"