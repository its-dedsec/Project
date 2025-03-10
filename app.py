"""
Streamlit application for network anomaly detection.
"""
import streamlit as st
import pandas as pd
import numpy as np
import tempfile
import os
import time
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# Import project modules
from network_capture import NetworkCapture
from data_preprocessing import TrafficPreprocessor
from anomaly_detection import AnomalyDetector
from threat_interpretation import ThreatInterpreter

# Set page configuration
st.set_page_config(
    page_title="Network Anomaly Detection",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'capture_running' not in st.session_state:
    st.session_state.capture_running = False
if 'results_df' not in st.session_state:
    st.session_state.results_df = None

def main():
    """Main function for the Streamlit application."""
    st.title("Network Anomaly Detection System")
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("Configuration")
        
        # Network configuration
        st.subheader("Network Settings")
        interface = st.text_input("Network Interface", value="eth0")
        local_network = st.text_input("Local Network CIDR", value="192.168.1.0/24")
        
        # Model configuration
        st.subheader("Model Settings")
        model_type = st.selectbox(
            "Anomaly Detection Model",
            ["isolation_forest", "one_class_svm"],
            index=0
        )
        contamination = st.slider(
            "Expected Anomaly Percentage", 
            min_value=0.01, 
            max_value=0.20, 
            value=0.05,
            step=0.01
        )
        
        # Capture settings
        st.subheader("Capture Settings")
        capture_duration = st.slider(
            "Capture Duration (seconds)", 
            min_value=5, 
            max_value=120, 
            value=30,
            step=5
        )
        
        # Add a button to start live capture
        start_capture = st.button("Start Live Capture")
        
        # Separator
        st.divider()
        
        # About section
        st.subheader("About")
        st.markdown("""
        This application detects network anomalies using machine learning.
        Upload a PCAP file or capture live traffic to analyze.
        """)
    
    # Main content area with tabs
    tab1, tab2, tab3, tab4 = st.tabs(["Upload & Analyze", "Capture Results", "Anomaly Details", "Threat Insights"])
    
    # Tab 1: Upload and Analyze
    with tab1:
        st.header("Upload & Analyze PCAP File")
        
        # File uploader
        uploaded_file = st.file_uploader("Choose a PCAP file", type=['pcap', 'pcapng'])
        
        # Process uploaded file
        if uploaded_file is not None:
            with st.spinner("Processing PCAP file..."):
                # Save uploaded file to temp location
                temp_dir = tempfile.mkdtemp()
                temp_path = os.path.join(temp_dir, uploaded_file.name)
                with open(temp_path, 'wb') as f:
                    f.write(uploaded_file.getvalue())
                
                # Process the file
                results_df = process_pcap_file(temp_path, local_network, model_type, contamination)
                st.session_state.results_df = results_df
                
                # Show success message
                st.success(f"Successfully processed {uploaded_file.name}")
                
                # Display basic statistics
                if results_df is not None:
                    display_basic_stats(results_df)
    
    # Tab 2: Capture Results
    with tab2:
        st.header("Live Capture Results")
        
        # Start live capture if button clicked
        if start_capture:
            if not st.session_state.capture_running:
                st.session_state.capture_running = True
                
                with st.spinner(f"Capturing network traffic for {capture_duration} seconds on interface {interface}..."):
                    # Perform live capture
                    capture = NetworkCapture(interface=interface)
                    try:
                        pcap_file = capture.capture_with_pyshark(duration=capture_duration)
                        st.success(f"Capture completed: {pcap_file}")
                        
                        # Process the captured file
                        results_df = process_pcap_file(pcap_file, local_network, model_type, contamination)
                        st.session_state.results_df = results_df
                        
                        # Display basic statistics
                        if results_df is not None:
                            display_basic_stats(results_df)
                    except Exception as e:
                        st.error(f"Error during capture: {str(e)}")
                
                st.session_state.capture_running = False
            else:
                st.warning("Capture already in progress. Please wait.")
        
        # Display capture results if available
        if st.session_state.results_df is not None:
            st.subheader("Processed Network Traffic")
            display_data_table(st.session_state.results_df)
    
    # Tab 3: Anomaly Details
    with tab3:
        st.header("Anomaly Detection Details")
        
        if st.session_state.results_df is not None:
            results_df = st.session_state.results_df
            
            # Display anomaly statistics
            anomaly_count = results_df['anomaly'].sum()
            total_count = len(results_df)
            anomaly_percentage = (anomaly_count / total_count) * 100 if total_count > 0 else 0
            
            # Create metrics row
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Packets", f"{total_count}")
            col2.metric("Anomalies Detected", f"{anomaly_count}")
            col3.metric("Anomaly Percentage", f"{anomaly_percentage:.2f}%")
            
            # Visual representation of anomalies
            st.subheader("Anomaly Visualization")
            
            # Create time-based anomaly chart
            if 'timestamp' in results_df.columns:
                fig = px.scatter(
                    results_df,
                    x='timestamp',
                    y='anomaly_score',
                    color='anomaly',
                    color_discrete_map={0: 'blue', 1: 'red'},
                    hover_data=['src_ip', 'dst_ip', 'protocol', 'length'],
                    title="Anomaly Scores Over Time"
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Show top anomalies
            st.subheader("Top Anomalies")
            top_anomalies = results_df[results_df['anomaly'] == 1].sort_values('anomaly_score', ascending=False)
            if len(top_anomalies) > 0:
                display_data_table(top_anomalies.head(10))
            else:
                st.info("No anomalies detected in this dataset.")
    
    # Tab 4: Threat Insights
    with tab4:
        st.header("Threat Interpretation")
        
        if st.session_state.results_df is not None:
            results_df = st.session_state.results_df
            
            # Get threats if available
            threats = results_df[results_df['threat_type'].notna()]
            
            if len(threats) > 0:
                # Display threat statistics
                st.subheader("Detected Threats")
                
                # Count threats by type
                threat_counts = threats['threat_type'].value_counts().reset_index()
                threat_counts.columns = ['Threat Type', 'Count']
                
                # Visualize threats
                fig = px.pie(
                    threat_counts, 
                    values='Count', 
                    names='Threat Type',
                    title="Threats by Type"
                )
                st.plotly_chart(fig, use_container_width=True)
                
                # Create tabs for each threat type
                threat_types = threats['threat_type'].unique()
                if len(threat_types) > 0:
                    threat_tabs = st.tabs(threat_types)
                    
                    for i, threat_type in enumerate(threat_types):
                        with threat_tabs[i]:
                            # Filter threats by type
                            type_threats = threats[threats['threat_type'] == threat_type]
                            
                            # Show details
                            st.markdown(f"### {threat_type.replace('_', ' ').title()}")
                            st.markdown(f"**Detected instances:** {len(type_threats)}")
                            
                            # Get a unique description
                            description = type_threats['threat_description'].iloc[0]
                            st.markdown(f"**Description:** {description}")
                            
                            # Show affected IPs
                            if 'src_ip' in type_threats.columns:
                                src_ips = type_threats['src_ip'].unique()
                                st.markdown(f"**Source IPs involved:** {', '.join(str(ip) for ip in src_ips if pd.notna(ip))}")
                            
                            if 'dst_ip' in type_threats.columns:
                                dst_ips = type_threats['dst_ip'].unique()
                                st.markdown(f"**Destination IPs involved:** {', '.join(str(ip) for ip in dst_ips if pd.notna(ip))}")
                            
                            # Show the related data
                            st.subheader("Related Traffic")
                            display_data_table(type_threats)
            else:
                st.info("No specific threats identified in the anomalies.")
                
                # Show general anomaly interpretation
                if 'anomaly' in results_df.columns and results_df['anomaly'].sum() > 0:
                    st.subheader("General Anomaly Characteristics")
                    
                    anomalies = results_df[results_df['anomaly'] == 1]
                    
                    # Show statistical differences between normal and anomalous traffic
                    st.markdown("#### Statistical Comparison: Normal vs. Anomalous Traffic")
                    
                    # Select numerical columns for comparison
                    num_cols = ['length', 'ttl'] if 'ttl' in results_df.columns else ['length']
                    
                    # Create comparison charts
                    for col in num_cols:
                        fig, ax = plt.subplots(figsize=(10, 4))
                        sns.histplot(
                            data=results_df, 
                            x=col, 
                            hue='anomaly', 
                            kde=True,
                            element="step", 
                            ax=ax
                        )
                        plt.title(f"Distribution of {col} by Traffic Type")
                        plt.xlabel(col)
                        plt.legend(['Normal', 'Anomalous'])
                        st.pyplot(fig)

def process_pcap_file(pcap_file, local_network, model_type, contamination):
    """
    Process a PCAP file through the full pipeline.
    
    Args:
        pcap_file (str): Path to the PCAP file
        local_network (str): CIDR notation for local network
        model_type (str): Type of anomaly detection model
        contamination (float): Expected proportion of anomalies
        
    Returns:
        pd.DataFrame: Results with anomaly detection and interpretation
    """
    try:
        # Step 1: Extract packets
        capture = NetworkCapture()
        packets = capture.extract_from_file(pcap_file)
        
        if not packets:
            st.error("No packets found in the PCAP file")
            return None
            
        # Step 2: Preprocess data
        preprocessor = TrafficPreprocessor()
        preprocessor.set_local_network(local_network)
        preprocessed_df = preprocessor.preprocess(packets)
        
        if preprocessed_df.empty:
            st.error("Failed to preprocess packets")
            return None
            
        # Step 3: Train model and detect anomalies
        detector = AnomalyDetector()
        detector.train(preprocessed_df, model_type=model_type, contamination=contamination)
        results_df = detector.predict(preprocessed_df)
        
        # Step 4: Interpret threats
        interpreter = ThreatInterpreter()
        results_df = interpreter.interpret_anomalies(results_df)
        
        return results_df
    except Exception as e:
        st.error(f"Error processing PCAP file: {str(e)}")
        return None

def display_basic_stats(df):
    """Display basic statistics about the processed data."""
    # Create columns for metrics
    col1, col2, col3, col4 = st.columns(4)
    
    # Show basic metrics
    col1.metric("Total Packets", f"{len(df)}")
    
    if 'protocol' in df.columns:
        top_protocol = df['protocol'].value_counts().index[0] if not df['protocol'].isna().all() else "Unknown"
        col2.metric("Top Protocol", f"{top_protocol}")
    
    if 'length' in df.columns:
        avg_size = df['length'].mean()
        col3.metric("Avg Packet Size", f"{avg_size:.1f} bytes")
    
    if 'anomaly' in df.columns:
        anomaly_pct = (df['anomaly'].sum() / len(df)) * 100
        col4.metric("Anomalies", f"{anomaly_pct:.2f}%")
    
    # Create a protocol distribution chart if protocol column exists
    if 'protocol' in df.columns and not df['protocol'].isna().all():
        st.subheader("Protocol Distribution")
        protocol_counts = df['protocol'].value_counts().reset_index()
        protocol_counts.columns = ['Protocol', 'Count']
        
        fig = px.pie(
            protocol_counts, 
            values='Count', 
            names='Protocol',
            title="Traffic by Protocol"
        )
        st.plotly_chart(fig, use_container_width=True)

def display_data_table(df, max_rows=1000):
    """Display a DataFrame as a table with pagination."""
    # Limit to most relevant columns
    display_cols = [
        'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
        'protocol', 'length', 'anomaly_score', 'anomaly', 
        'threat_type', 'threat_description'
    ]
    
    # Only include columns that exist in the DataFrame
    display_cols = [col for col in display_cols if col in df.columns]
    
    # Limit number of rows to prevent performance issues
    if len(df) > max_rows:
        st.warning(f"Showing only the first {max_rows} rows.")
        display_df = df[display_cols].head(max_rows)
    else:
        display_df = df[display_cols]
    
    # Convert timestamp to readable format if present
    if 'timestamp' in display_df.columns:
        display_df['timestamp'] = pd.to_datetime(display_df['timestamp'], unit='s')
    
    # Display the table with row highlighting based on anomaly status
    st.dataframe(
        display_df.style.apply(
            lambda row: ['background-color: rgba(255, 0, 0, 0.2)' if row['anomaly'] == 1 else '' for _ in row],
            axis=1
        ) if 'anomaly' in display_df.columns else display_df,
        use_container_width=True
    )

if __name__ == "__main__":
    main()
