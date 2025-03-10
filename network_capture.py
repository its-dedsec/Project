# capture.py
import pyshark
import time

def capture_traffic(output_file="captured_traffic.pcap", duration=10):
    """
    Captures network traffic and saves it to a .pcap file.

    Args:
        output_file (str): The name of the output .pcap file.
        duration (int): The capture duration in seconds.
    """
    try:
        capture = pyshark.LiveCapture(output_file=output_file)
        capture.sniff(timeout=duration)
        print(f"Captured traffic saved to {output_file}")
    except Exception as e:
        print(f"Error capturing traffic: {e}")

if __name__ == "__main__":
    capture_traffic()
