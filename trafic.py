import pyshark

def categorize_traffic(packet):
    if 'HTTP' in packet:
        with open('http_traffic.txt', 'a') as f:
            f.write(f"{packet}\n")
    elif 'TLS' in packet:
        with open('https_traffic.txt', 'a') as f:
            f.write(f"{packet}\n")
    elif 'FTP' in packet:
        with open('ftp_traffic.txt', 'a') as f:
            f.write(f"{packet}\n")
    else:
        with open('other_traffic.txt', 'a') as f:
            f.write(f"{packet}\n")

def capture_traffic():
    capture = pyshark.LiveCapture(interface='enp2s0')
    for packet in capture.sniff_continuously():
        print(f"Packet captured: {packet}")
        categorize_traffic(packet)

if __name__ == "__main__":
    capture_traffic()
