import sys

def main():
    data = sys.stdin.buffer.read()
    if b"PCAP_BEGIN" not in data or b"PCAP_END" not in data:
        print("Error: Could not find PCAP_BEGIN / PCAP_END markers in input stream.", file=sys.stderr)
        sys.exit(1)

    # Strip console lines (prompt noise between PCAP_BEGIN and PCAP_END)
    start = data.index(b"PCAP_BEGIN") + len(b"PCAP_BEGIN\n")
    end   = data.index(b"PCAP_END", start)
    body  = data[start:end]
    out = bytearray()
    i = 0
    while i + 4 <= len(body):
        n = int.from_bytes(body[i:i+4], "big")
        i += 4
        out += body[i:i+n]
        i += n

    out_filename = "capture.pcap"
    if len(sys.argv) > 1:
        out_filename = sys.argv[1]

    with open(out_filename, "wb") as f:
        f.write(bytes(out))

    print(f"wrote {out_filename} ({len(out)} bytes)")

if __name__ == "__main__":
    main()
