"""
Module for preprocessing network traffic data.
"""
import pandas as pd
import numpy as np
import ipaddress
import logging
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TrafficPreprocessor:
    """Class to preprocess network traffic data for anomaly detection."""
    
    def __init__(self):
        """Initialize the preprocessor."""
        self.feature_stats = {}
        self.ip_info = defaultdict(lambda: {'incoming': 0, 'outgoing': 0})
        self.local_network = None
        
    def _is_local_ip(self, ip):
        """Check if an IP is in the local network."""
        if self.local_network is None:
            return False
        try:
            return ipaddress.ip_address(ip) in self.local_network
        except:
            return False
            
    def set_local_network(self, network_cidr):
        """
        Set the local network CIDR.
        
        Args:
            network_cidr (str): CIDR notation for local network (e.g., '192.168.1.0/24')
        """
        try:
            self.local_network = ipaddress.ip_network(network_cidr)
            logger.info(f"Local network set to {network_cidr}")
        except ValueError as e:
            logger.error(f"Invalid CIDR notation: {e}")
            
    def extract_basic_features(self, packets):
    """
    Extract basic features from packets.

    Args:
        packets (list): List of packet objects from pyshark

    Returns:
        pd.DataFrame: DataFrame with basic features
    """
    logger.info("Extracting basic features from packets")
    data =# Assign an empty list to data

    for i, packet in enumerate(packets):
        try:
                # Initialize with default values
                pkt_data = {
                    'timestamp': float(packet.sniff_time.timestamp()),
                    'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else packet.highest_layer,
                    'length': int(packet.length),
                    'src_ip': None,
                    'dst_ip': None,
                    'src_port': None, 
                    'dst_port': None,
                    'ttl': None,
                }
                
                # Extract IP-related data if available
                if hasattr(packet, 'ip'):
                    pkt_data.update({
                        'src_ip': packet.ip.src,
                        'dst_ip': packet.ip.dst,
                        'ttl': int(packet.ip.ttl),
                    })
                    
                    # Update IP info for feature engineering
                    self.ip_info[packet.ip.src]['outgoing'] += int(packet.length)
                    self.ip_info[packet.ip.dst]['incoming'] += int(packet.length)
                    
                # Extract transport layer data if available
                if hasattr(packet, 'tcp'):
                    pkt_data.update({
                        'src_port': int(packet.tcp.srcport),
                        'dst_port': int(packet.tcp.dstport),
                    })
                elif hasattr(packet, 'udp'):
                    pkt_data.update({
                        'src_port': int(packet.udp.srcport),
                        'dst_port': int(packet.udp.dstport),
                    })
                    
                data.append(pkt_data)
            except Exception as e:
                logger.warning(f"Error processing packet {i}: {e}")
                continue
                
        df = pd.DataFrame(data)
        logger.info(f"Extracted {len(df)} records with basic features")
        return df
        
    def engineer_features(self, df, window_size=10):
        """
        Engineer additional features for anomaly detection.
        
        Args:
            df (pd.DataFrame): DataFrame with basic features
            window_size (int): Window size for rolling statistics
            
        Returns:
            pd.DataFrame: DataFrame with engineered features
        """
        logger.info("Engineering additional features")
        
        # Sort by timestamp
        df = df.sort_values('timestamp').reset_index(drop=True)
        
        # Add time-based features
        df['hour'] = pd.to_datetime(df['timestamp'], unit='s').dt.hour
        df['minute'] = pd.to_datetime(df['timestamp'], unit='s').dt.minute
        
        # Add rolling statistics
        df['rolling_mean_length'] = df['length'].rolling(window=window_size, min_periods=1).mean()
        df['rolling_std_length'] = df['length'].rolling(window=window_size, min_periods=1).std().fillna(0)
        
        # Add IP-based flags and features
        df['ip_traffic_ratio'] = df.apply(
            lambda row: self._calculate_ip_ratio(row['src_ip']) if row['src_ip'] else np.nan, 
            axis=1
        )
        
        # Convert protocols to numerical using one-hot encoding
        protocol_dummies = pd.get_dummies(df['protocol'], prefix='protocol')
        df = pd.concat([df, protocol_dummies], axis=1)
        
        # Flag unusual ports
        common_ports = [80, 443, 22, 53, 123, 20, 21, 25, 110, 143, 993, 995, 8080]
        df['unusual_src_port'] = df['src_port'].apply(lambda x: 0 if x in common_ports else 1)
        df['unusual_dst_port'] = df['dst_port'].apply(lambda x: 0 if x in common_ports else 1)
        
        # Handle missing values
        df = df.fillna({
            'ttl': df['ttl'].median() if not df['ttl'].isna().all() else 64,
            'src_port': -1,
            'dst_port': -1,
            'ip_traffic_ratio': 1.0
        })
        
        # Calculate communication pair frequency
        if not df['src_ip'].isna().all() and not df['dst_ip'].isna().all():
            communication_pairs = df.groupby(['src_ip', 'dst_ip']).size().reset_index(name='pair_frequency')
            pair_dict = dict(zip(zip(communication_pairs['src_ip'], communication_pairs['dst_ip']), 
                                communication_pairs['pair_frequency']))
            df['pair_frequency'] = df.apply(lambda row: pair_dict.get((row['src_ip'], row['dst_ip']), 0), axis=1)
            df['rare_communication'] = df['pair_frequency'].apply(lambda x: 1 if x <= 2 else 0)
        
        # Store feature statistics for scaling in the anomaly detection phase
        self.feature_stats = {
            'length_mean': df['length'].mean(),
            'length_std': df['length'].std(),
            'ttl_mean': df['ttl'].mean(),
            'ttl_std': df['ttl'].std(),
        }
        
        logger.info(f"Engineered features added, final dataframe has {df.shape[1]} columns")
        return df
    
    def _calculate_ip_ratio(self, ip):
        """Calculate the ratio of outgoing to incoming traffic for an IP."""
        info = self.ip_info[ip]
        if info['incoming'] == 0:
            return info['outgoing'] if info['outgoing'] > 0 else 1.0
        return info['outgoing'] / info['incoming']
        
    def preprocess(self, packets, output_file=None):
        """
        Preprocess packets for anomaly detection.
        
        Args:
            packets (list): List of packet objects from pyshark
            output_file (str, optional): Path to save the preprocessed data
            
        Returns:
            pd.DataFrame: Preprocessed data
        """
        logger.info("Starting preprocessing of packet data")
        
        # Extract basic features
        df = self.extract_basic_features(packets)
        
        # Skip further processing if no packets were processed
        if df.empty:
            logger.warning("No packets could be processed")
            return df
            
        # Engineer additional features
        df = self.engineer_features(df)
        
        # Save to CSV if output file specified
        if output_file:
            df.to_csv(output_file, index=False)
            logger.info(f"Preprocessed data saved to {output_file}")
            
        return df

# Example usage
if __name__ == "__main__":
    import pyshark
    # Load sample pcap file
    sample_pcap = "sample.pcap"
    try:
        capture = pyshark.FileCapture(sample_pcap)
        packets = [packet for packet in capture]
        
        preprocessor = TrafficPreprocessor()
        preprocessor.set_local_network('192.168.1.0/24')
        df = preprocessor.preprocess(packets, "preprocessed_data.csv")
        
        print(f"Preprocessed {len(df)} packets with {df.shape[1]} features")
        print(f"Sample of preprocessed data:\n{df.head()}")
    except Exception as e:
        print(f"Error in preprocessing example: {e}")
