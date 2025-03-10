# analyze.py
import pandas as pd

def interpret_anomalies(df):
    """
    Provides basic interpretation of detected anomalies.

    Args:
        df (pandas.DataFrame): DataFrame with anomaly labels.

    Returns:
        pandas.DataFrame: DataFrame with interpretation.
    """
    try:
        anomalous_packets = df[df["anomaly"] == "anomalous"]
        interpretations = []
        for _, row in anomalous_packets.iterrows():
            interpretation = "Unusual activity detected: "
            if row["length"] > 1500:
                interpretation += "High traffic volume, "
            if row["src_port"] < 1024 or row["dst_port"] < 1024:
                interpretation += "Unusual port activity, "
            interpretations.append(interpretation.rstrip(", "))
        anomalous_packets["interpretation"] = interpretations
        return anomalous_packets
    except Exception as e:
        print(f"Error interpreting anomalies: {e}")
        return None

if __name__ == "__main__":
    df = pd.read_csv("preprocessed_data.csv")
    model, features = train_anomaly_model()
    if model is not None:
        result = detect_anomalies(model, features)
        if result is not None:
            interpreted_results = interpret_anomalies(result)
            if interpreted_results is not None:
                print(interpreted_results)
