import os
import subprocess
import datetime
import pyshark
import tempfile
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NetworkCapture:
    """Class to handle network traffic capture using tcpdump or pyshark."""
    
    def __init__(self, interface='eth0', output_dir='./data'):
        """
        Initialize NetworkCapture.
        
        Args:
            interface (str): Network interface to capture traffic from
            output_dir (str): Directory to save captured traffic files
        """
        self.interface = interface
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
    def capture_with_tcpdump(self, duration=30, filename=None):
        """
        Capture network traffic using tcpdump.
        
        Args:
            duration (int): Duration in seconds to capture traffic
            filename (str, optional): Output filename, default is timestamp-based
            
        Returns:
            str: Path to the captured pcap file
        """
        if filename is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"capture_{timestamp}.pcap"
            
        output_path = os.path.join(self.output_dir, filename)
        
        try:
            logger.info(f"Starting tcpdump capture on interface {self.interface} for {duration} seconds")
            subprocess.run(
                ["tcpdump", "-i", self.interface, "-w", output_path, "-G", str(duration), "-W", "1"],
                check=True
            )
            logger.info(f"Capture completed and saved to {output_path}")
            return output_path
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to capture traffic with tcpdump: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during tcpdump capture: {e}")
            raise
            
    def capture_with_pyshark(self, duration=30, filename=None, packet_count=None):
        """
        Capture network traffic using pyshark (wrapper for tshark).
        
        Args:
            duration (int): Duration in seconds to capture traffic
            filename (str, optional): Output filename, default is timestamp-based
            packet_count (int, optional): Number of packets to capture
            
        Returns:
            str: Path to the captured pcap file
        """
        if filename is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"capture_{timestamp}.pcap"
            
        output_path = os.path.join(self.output_dir, filename)
        
        try:
            # Set capture parameters
            capture = pyshark.LiveCapture(interface=self.interface, output_file=output_path)
            
            logger.info(f"Starting pyshark capture on interface {self.interface}")
            
            # Capture based on packet count or duration
            if packet_count:
                capture.sniff(packet_count=packet_count)
            else:
                capture.sniff(timeout=duration)
                
            logger.info(f"Capture completed and saved to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to capture traffic with pyshark: {e}")
            raise
            
    def extract_from_file(self, pcap_file):
        """
        Extract packets from an existing pcap file.
        
        Args:
            pcap_file (str): Path to the pcap file
            
        Returns:
            list: List of packet objects
        """
        try:
            logger.info(f"Reading packets from {pcap_file}")
            capture = pyshark.FileCapture(pcap_file)
            packets = [packet for packet in capture]
            logger.info(f"Read {len(packets)} packets from file")
            return packets
        except Exception as e:
            logger.error(f"Failed to extract packets from {pcap_file}: {e}")
            raise

# Example usage
if __name__ == "__main__":
    capture = NetworkCapture()
    pcap_file = capture.capture_with_pyshark(duration=10)
    packets = capture.extract_from_file(pcap_file)
    print(f"Captured {len(packets)} packets")
