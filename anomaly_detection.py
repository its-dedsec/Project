# model.py
import pandas as pd
from sklearn.ensemble import IsolationForest

def train_anomaly_model(input_file="preprocessed_data.csv"):
    """
    Trains an anomaly detection model.

    Args:
        input_file (str): The input .csv file.

    Returns:
        tuple: Trained model and feature names.
    """
    try:
        df = pd.read_csv(input_file)
        features = df[["src_port", "dst_port", "length"]]
        model = IsolationForest(contamination=0.05)  # Adjust contamination as needed
        model.fit(features)
        return model, features.columns
    except Exception as e:
        print(f"Error training model: {e}")
        return None, None

def detect_anomalies(model, features, input_file="preprocessed_data.csv"):
    """
    Detects anomalies in the preprocessed data.

    Args:
        model: Trained anomaly detection model.
        features: Feature names.
        input_file (str): The input .csv file.

    Returns:
        pandas.DataFrame: DataFrame with anomaly labels.
    """
    try:
        df = pd.read_csv(input_file)
        predictions = model.predict(df[features])
        df["anomaly"] = predictions
        df["anomaly"] = df["anomaly"].map({1: "normal", -1: "anomalous"})
        return df
    except Exception as e:
        print(f"Error detecting anomalies: {e}")
        return None

if __name__ == "__main__":
    model, features = train_anomaly_model()
    if model is not None:
        result = detect_anomalies(model, features)
        if result is not None:
            print(result)
