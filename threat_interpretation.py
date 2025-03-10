"""
Module for interpreting detected network anomalies.
"""
import pandas as pd
import numpy as np
import logging
from collections import Counter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ThreatInterpreter:
    """Class for interpreting and classifying detected network anomalies."""
    
    def __init__(self):
        """Initialize the threat interpreter."""
        self.threat_patterns = {
            'port_scan': {
                'description': 'Possible port scanning activity',
                'indicators': ['multiple destination ports from same source', 'small packet size', 'rare communication']
            },
            'ddos': {
                'description': 'Possible DDoS or flooding attack',
                'indicators': ['high volume from one source', 'uniform packet size', 'unusual traffic pattern']
            },
            'data_exfiltration': {
                'description': 'Possible data exfiltration',
                'indicators': ['large outbound transfers', 'unusual destination', 'unusual hour of activity']
            },
            'malware_communication': {
                'description': 'Possible malware communication',
                'indicators': ['unusual ports', 'periodic communication', 'unusual protocol usage']
            },
            'unauthorized_access': {
                'description': 'Possible unauthorized access attempt',
                'indicators': ['sensitive ports targeted', 'failed connection attempts', 'unusual source']
            },
            'uncommon_protocol': {
                'description': 'Uncommon protocol usage',
                'indicators': ['rare protocol', 'unusual for this network']
            }
        }
        
    def _check_port_scan(self, group_df):
        """
        Check if a group of packets exhibits port scanning behavior.
        
        Args:
            group_df (pd.DataFrame): Group of packets from the same source IP
            
        Returns:
            bool: True if port scanning is detected
        """
        if len(group_df) < 5:
            return False
            
        # Check for many unique destination ports from the same source
        unique_dest_ports = group_df['dst_port'].nunique()
        if unique_dest_ports < 5:
            return False
            
        # Check for small packet sizes (typical of port scans)
        avg_packet_size = group_df['length'].mean()
        if avg_packet_size > 100:  # Most port scans use small packets
            return False
            
        # Check time window - port scans typically happen in a short time
        time_range = group_df['timestamp'].max() - group_df['timestamp'].min()
        if time_range > 60:  # More than 60 seconds might not be a port scan
            return False
            
        return True
        
    def _check_ddos(self, group_df):
        """
        Check if a group of packets exhibits DDoS behavior.
        
        Args:
            group_df (pd.DataFrame): Group of packets to the same destination IP
            
        Returns:
            bool: True if DDoS pattern is detected
        """
        if len(group_df) < 20:  # Need significant volume
            return False
            
        # Check packet rate (packets per second)
        time_range = group_df['timestamp'].max() - group_df['timestamp'].min()
        if time_range < 0.001:  # Avoid division by zero
            return False
            
        packet_rate = len(group_df) / time_range
        if packet_rate < 10:  # Less than 10 packets per second is probably not a DDoS
            return False
            
        # Check uniformity of packet sizes (common in automated attacks)
        packet_size_std = group_df['length'].std()
        if packet_size_std > 100:  # High variance in packet size less indicative of DDoS
            return False
            
        return True
        
    def _check_data_exfiltration(self, group_df, threshold_mb=1):
        """
        Check if a group of packets exhibits data exfiltration behavior.
        
        Args:
            group_df (pd.DataFrame): Group of packets to check
            threshold_mb (float): Threshold in MB to consider as large transfer
            
        Returns:
            bool: True if data exfiltration pattern is detected
        """
        # Convert threshold to bytes for comparison
        threshold_bytes = threshold_mb * 1024 * 1024
        
        # Calculate total outbound data
        total_bytes = group_df['length'].sum()
        if total_bytes < threshold_bytes:
            return False
            
        # Check if destination is unusual 
        # (Could be enhanced with historical data or reputation lists)
        unusual_dst = group_df['unusual_dst_port'].mean() > 0.5
        
        # Check if data transfer happened during unusual hours
        unusual_hours = [0, 1, 2, 3, 4, 5, 23]  # Define unusual hours
        avg_hour = group_df['hour'].mean()
        unusual_time = int(avg_hour) in unusual_hours
        
        return unusual_dst or unusual_time
        
    def _check_malware_communication(self, group_df):
        """
        Check if a group of packets exhibits patterns typical of malware communication.
        
        Args:
            group_df (pd.DataFrame): Group of packets to check
            
        Returns:
            bool: True if malware communication pattern is detected
        """
        # Check for uncommon ports
        common_ports = [80, 443, 22, 53, 123, 20, 21, 25, 110, 143, 993, 995, 8080]
        ports_used = set(group_df['dst_port'].unique())
        uncommon_ports = ports_used.difference(common_ports)
        
        if not uncommon_ports:
            return False
            
        # Check for periodic communication
        if len(group_df) >= 3:
            timestamps = sorted(group_df['timestamp'].values)
            intervals = np.diff(timestamps)
            interval_variation = np.std(intervals) / np.mean(intervals) if np.mean(intervals) > 0 else float('inf')
            
            # Low variation in intervals suggests periodic communication
            periodic = interval_variation < 0.5 and len(group_df) >= 3
            if periodic:
                return True
                
        # Check for unusual protocol usage
        protocol_cols = [col for col in group_df.columns if col.startswith('protocol_')]
        if protocol_cols:
            for col in protocol_cols:
                if col != 'protocol_TCP' and col != 'protocol_UDP' and col != 'protocol_ICMP':
                    if group_df[col].mean() > 0:
                        return True
                        
        return False
        
    def interpret_anomalies(self, df):
        """
        Interpret detected anomalies and identify potential threats.
        
        Args:
            df (pd.DataFrame): DataFrame with anomaly detection results
            
        Returns:
            pd.DataFrame: DataFrame with threat interpretations
        """
        if 'anomaly' not in df.columns:
            raise ValueError("Input DataFrame must contain 'anomaly' column")
            
        logger.info("Interpreting detected anomalies")
        
        # Only analyze anomalous packets
        anomalies = df[df['anomaly'] == 1].copy()
        
        if len(anomalies) == 0:
            logger.info("No anomalies to interpret")
            df['threat_type'] = None
            df['threat_description'] = None
            return df
            
        # Initialize threat columns
        anomalies['threat_type'] = None
        anomalies['threat_description'] = None
        
        # Group by source IP
        if 'src_ip' in anomalies.columns and not anomalies['src_ip'].isna().all():
            for src_ip, group in anomalies.groupby('src_ip'):
                # Skip if too few packets
                if len(group) < 3:
                    continue
                    
                # Check for port scanning
                if self._check_port_scan(group):
                    idx = group.index
                    anomalies.loc[idx, 'threat_type'] = 'port_scan'
                    anomalies.loc[idx, 'threat_description'] = f"Possible port scan from {src_ip}"
                    
                # Check for data exfiltration
                elif self._check_data_exfiltration(group):
                    idx = group.index
                    anomalies.loc[idx, 'threat_type'] = 'data_exfiltration'
                    anomalies.loc[idx, 'threat_description'] = f"Possible data exfiltration from {src_ip}"
                    
                # Check for malware communication
                elif self._check_malware_communication(group):
                    idx = group.index
                    anomalies.loc[idx, 'threat_type'] = 'malware_communication'
                    anomalies.loc[idx, 'threat_description'] = f"Suspicious communication pattern from {src_ip}"
                    
        # Group by destination IP
        if 'dst_ip' in anomalies.columns and not anomalies['dst_ip'].isna().all():
            for dst_ip, group in anomalies.groupby('dst_ip'):
                # Check for DDoS or flooding
                if self._check_ddos(group):
                    idx = group.index
                    anomalies.loc[idx, 'threat_type'] = 'ddos'
                    anomalies.loc[idx, 'threat_description'] = f"Possible DDoS attack targeting {dst_ip}"
                    
        # Identify other anomalies
        remaining_anomalies = anomalies[anomalies['threat_type'].isna()]
        if len(remaining_anomalies) > 0:
            # Check for unusual ports
            unusual_ports = remaining_anomalies['unusual_dst_port'] == 1
            if unusual_ports.any():
                idx = remaining_anomalies[unusual_ports].index
                anomalies.loc[idx, 'threat_type'] = 'unauthorized_access'
                anomalies.loc[idx, 'threat_description'] = "Connection attempt to unusual port"
            
            # Check for uncommon protocols
            protocol_cols = [col for col in remaining_anomalies.columns if col.startswith('protocol_')]
            if protocol_cols:
                for col in protocol_cols:
                    if col not in ['protocol_TCP', 'protocol_UDP', 'protocol_ICMP']:
                        unusual_protocol = remaining_anomalies[col] == 1
                        if unusual_protocol.any():
                            idx = remaining_anomalies[unusual_protocol].index
                            protocol_name = col.replace('protocol_', '')
                            anomalies.loc[idx, 'threat_type'] = 'uncommon_protocol'
                            anomalies.loc[idx, 'threat_description'] = f"Uncommon protocol usage: {protocol_name}"
        
        # Update the original DataFrame with threat information
        result_df = df.copy()
        result_df['threat_type'] = None
        result_df['threat_description'] = None
        
        # Copy threat information from anomalies DataFrame
        anomaly_indices = anomalies.index
        result_df.loc[anomaly_indices, 'threat_type'] = anomalies.loc[anomaly_indices, 'threat_type']
        result_df.loc[anomaly_indices, 'threat_description'] = anomalies.loc[anomaly_indices, 'threat_description']
        
        logger.info(f"Interpreted {len(anomalies)} anomalies, identified {anomalies['threat_type'].notna().sum()} threats")
        return result_df
        
    def get_threat_summary(self, df):
        """
        Generate a summary of detected threats.
        
        Args:
            df (pd.DataFrame): DataFrame with threat interpretations
            
        Returns:
            dict: Summary of detected threats
        """
        if 'threat_type' not in df.columns:
            return {'threats_detected': 0}
            
        # Count threats by type
        threats = df[df['threat_type'].notna()]
        threat_counts = threats['threat_type'].value_counts().to_dict()
        
        # Generate summary
        summary = {
            'threats_detected': len(threats),
            'threat_types': threat_counts,
            'affected_src_ips': threats['src_ip'].nunique() if 'src_ip' in threats.columns else 0,
            'affected_dst_ips': threats['dst_ip'].nunique() if 'dst_ip' in threats.columns else 0
        }
        
        return summary

# Example usage
if __name__ == "__main__":
    # Create sample data with anomalies
    try:
        data = pd.read_csv("anomaly_results.csv")
        
        interpreter = ThreatInterpreter()
        results = interpreter.interpret_anomalies(data)
        
        summary = interpreter.get_threat_summary(results)
        print(f"Threat summary: {summary}")
        
        if summary['threats_detected'] > 0:
            print("\nDetected threats:")
            for threat_type, count in summary['threat_types'].items():
                print(f"- {threat_type}: {count} instances")
    except Exception as e:
        print(f"Error in threat interpretation example: {e}")
