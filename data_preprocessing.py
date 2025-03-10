# preprocess.py
import pyshark
import pandas as pd

def preprocess_traffic(input_file="captured_traffic.pcap", output_file="preprocessed_data.csv"):
    """
    Preprocesses network traffic data and saves it to a .csv file.

    Args:
        input_file (str): The input .pcap file.
        output_file (str): The output .csv file.
    """
    try:
        capture = pyshark.FileCapture(input_file)
        data = []
        for packet in capture:
            try:
                protocol = packet.transport_layer
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = packet[protocol].srcport
                dst_port = packet[protocol].dstport
                length = int(packet.length)
                data.append([protocol, src_ip, dst_ip, src_port, dst_port, length])
            except AttributeError:
                pass  # Skip packets without necessary layers

        df = pd.DataFrame(data, columns=["protocol", "src_ip", "dst_ip", "src_port", "dst_port", "length"])
        df.to_csv(output_file, index=False)
        print(f"Preprocessed data saved to {output_file}")
    except Exception as e:
        print(f"Error preprocessing data: {e}")

if __name__ == "__main__":
    preprocess_traffic()
