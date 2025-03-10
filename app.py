# app.py
import streamlit as st
import pandas as pd
from capture import capture_traffic
from preprocess import preprocess_traffic
from model import train_anomaly_model, detect_anomalies
from analyze import interpret_anomalies
import os

st.title("Network Anomaly Detection")

uploaded_file = st.file_uploader("Upload .pcap file", type="pcap")

if uploaded_file is not None:
    with open("uploaded_traffic.pcap", "wb") as f:
        f.write(uploaded_file.getbuffer())

    preprocess_traffic("uploaded_traffic.pcap", "uploaded_preprocessed_data.csv")
    model, features = train_anomaly_model("uploaded_preprocessed_data.csv")
    if model is not None:
        result = detect_anomalies(model, features, "uploaded_preprocessed_data.csv")
        if result is not None:
            st.write("Preprocessed Data:")
            st.dataframe(result)
            interpreted_results = interpret_anomalies(result)
            if interpreted_results is not None:
                st.write("Anomalous Packets and Interpretation:")
                st.dataframe(interpreted_results)

if st.button("Capture Live Traffic"):
    capture_traffic()
    preprocess_traffic()
    model, features = train_anomaly_model()
    if model is not None:
        result = detect_anomalies(model, features)
        if result is not None:
            st.write("Live Traffic Analysis:")
            st.dataframe(result)
            interpreted_results = interpret_anomal
