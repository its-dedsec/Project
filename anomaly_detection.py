"""
Module for network traffic anomaly detection.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib
import logging
from datetime import datetime
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AnomalyDetector:
    """Class for detecting anomalies in network traffic data."""
    
    def __init__(self, model_dir='./models'):
        """
        Initialize the anomaly detector.
        
        Args:
            model_dir (str): Directory to save trained models
        """
        self.model_dir = model_dir
        self.model = None
        self.features = []
        self.numeric_columns = []
        self.categorical_columns = []
        
        # Create model directory if it doesn't exist
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
            
    def _identify_columns(self, df):
        """Identify numeric and categorical columns for processing."""
        # Skip these columns from model features
        skip_columns = ['timestamp', 'src_ip', 'dst_ip', 'protocol']
        
        # Identify numeric columns (excluding specific columns)
        self.numeric_columns = [col for col in df.columns if 
                              col not in skip_columns and 
                              pd.api.types.is_numeric_dtype(df[col])]
        
        # Identify categorical columns (currently handled via one-hot encoding in preprocessing)
        self.categorical_columns = [col for col in df.columns if 
                                  col not in skip_columns and 
                                  col not in self.numeric_columns]
        
        # Features to use in the model
        self.features = self.numeric_columns + [col for col in self.categorical_columns 
                                              if col.startswith('protocol_')]
        
        logger.info(f"Using features for anomaly detection: {self.features}")
            
    def train(self, df, model_type='isolation_forest', contamination=0.05):
        """
        Train an anomaly detection model.
        
        Args:
            df (pd.DataFrame): Preprocessed network traffic data
            model_type (str): Type of model to use ('isolation_forest' or 'one_class_svm')
            contamination (float): Expected proportion of outliers in the data
            
        Returns:
            self: Trained model instance
        """
        logger.info(f"Training {model_type} model with contamination={contamination}")
        
        self._identify_columns(df)
        
        X = df[self.features].copy()
        
        # Create the model pipeline with standardization
        if model_type == 'isolation_forest':
            self.model = Pipeline([
                ('scaler', StandardScaler()),
                ('model', IsolationForest(
                    contamination=contamination,
                    random_state=42,
                    n_estimators=100
                ))
            ])
        elif model_type == 'one_class_svm':
            self.model = Pipeline([
                ('scaler', StandardScaler()),
                ('model', OneClassSVM(
                    nu=contamination,
                    kernel='rbf',
                    gamma='auto'
                ))
            ])
        else:
            raise ValueError(f"Unsupported model type: {model_type}")
            
        # Train the model
        self.model.fit(X)
        
        # Save the trained model
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_filename = os.path.join(self.model_dir, f"{model_type}_{timestamp}.joblib")
        joblib.dump(self.model, model_filename)
        logger.info(f"Model saved to {model_filename}")
        
        return self
        
    def predict(self, df):
        """
        Detect anomalies in network traffic data.
        
        Args:
            df (pd.DataFrame): Preprocessed network traffic data
            
        Returns:
            pd.DataFrame: Original data with anomaly scores and predictions
        """
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
            
        logger.info("Detecting anomalies in network traffic data")
        
        # Ensure all required features are present
        for feature in self.features:
            if feature not in df.columns:
                if feature.startswith('protocol_'):
                    df[feature] = 0  # Add missing protocol features as 0
                else:
                    raise ValueError(f"Required feature '{feature}' not found in input data")
        
        X = df[self.features].copy()
        
        # Get anomaly scores - convert to positive values where higher means more anomalous
        # For Isolation Forest and One-Class SVM, negative values are outliers
        raw_scores = self.model.decision_function(X)
        df['anomaly_score'] = -raw_scores  # Invert so higher values = more anomalous
        
        # Predict anomalies (1 for normal, -1 for anomalies - convert to 0/1 for simplicity)
        raw_predictions = self.model.predict(X)
        df['anomaly'] = np.where(raw_predictions == -1, 1, 0)  # 1 if anomaly, 0 if normal
        
        anomaly_count = df['anomaly'].sum()
        logger.info(f"Detected {anomaly_count} anomalies out of {len(df)} records ({anomaly_count/len(df)*100:.2f}%)")
        
        return df
        
    def load_model(self, model_path):
        """
        Load a saved anomaly detection model.
        
        Args:
            model_path (str): Path to the saved model file
            
        Returns:
            self: Model instance with loaded model
        """
        logger.info(f"Loading model from {model_path}")
        self.model = joblib.load(model_path)
        return self
        
    def get_feature_importance(self, df):
        """
        Get feature importance if available.
        
        Args:
            df (pd.DataFrame): Preprocessed data with the same features as training data
            
        Returns:
            dict: Feature importance scores
        """
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
            
        # Only works for Isolation Forest
        if hasattr(self.model['model'], 'feature_importances_'):
            importances = self.model['model'].feature_importances_
            return dict(zip(self.features, importances))
        else:
            logger.warning("Feature importance not available for this model type")
            return {}

# Example usage
if __name__ == "__main__":
    # Load sample preprocessed data
    try:
        df = pd.read_csv("preprocessed_data.csv")
        
        # Train anomaly detection model
        detector = AnomalyDetector()
        detector.train(df, model_type='isolation_forest', contamination=0.05)
        
        # Detect anomalies
        results = detector.predict(df)
        
        print(f"Total records: {len(results)}")
        print(f"Anomalies detected: {results['anomaly'].sum()}")
        print(f"Top 5 anomalies by score:")
        top_anomalies = results.sort_values('anomaly_score', ascending=False).head(5)
        print(top_anomalies[['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length', 'anomaly_score']])
    except Exception as e:
        print(f"Error in anomaly detection example: {e}")
