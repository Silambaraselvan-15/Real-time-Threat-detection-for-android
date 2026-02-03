"""
Network Anomaly Detection using Isolation Forest
Analyzes captured network data for anomalies
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json
import os
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class NetworkAnomalyDetector:
    def __init__(self, contamination=0.1):
        """
        Initialize anomaly detector
        
        Args:
            contamination: Expected proportion of anomalies (0-1)
        """
        self.contamination = contamination
        self.iso_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.model_trained = False
        self.anomalies = []
        self.normal_traffic = []
    
    def load_ip_data(self, csv_path):
        """Load and preprocess IP data"""
        try:
            df = pd.read_csv(csv_path)
            print(f"[+] Loaded {len(df)} IP records")
            return df
        except Exception as e:
            print(f"[-] Error loading IP data: {e}")
            return None
    
    def load_dns_data(self, csv_path):
        """Load DNS data"""
        try:
            df = pd.read_csv(csv_path)
            print(f"[+] Loaded {len(df)} DNS records")
            return df
        except Exception as e:
            print(f"[-] Error loading DNS data: {e}")
            return None
    
    def extract_features(self, ip_df):
        """Extract features for anomaly detection"""
        features = pd.DataFrame()
        
        # IP-based features
        features['ttl'] = ip_df['ttl']
        features['packet_length'] = ip_df['packet_length']
        features['fragmented'] = ip_df['fragmented'].astype(int)
        
        # Encode protocol
        protocol_mapping = {'tcp': 6, 'udp': 17, 'icmp': 1}
        features['protocol'] = ip_df['protocol']
        
        # Count packets per source IP
        src_ip_counts = ip_df['src_ip'].value_counts()
        features['src_ip_freq'] = ip_df['src_ip'].map(src_ip_counts)
        
        # Count packets per destination IP
        dst_ip_counts = ip_df['dst_ip'].value_counts()
        features['dst_ip_freq'] = ip_df['dst_ip'].map(dst_ip_counts)
        
        # Flag suspicious characteristics
        features['is_suspicious_ttl'] = (features['ttl'] < 5) | (features['ttl'] > 250)
        features['is_suspicious_size'] = features['packet_length'] > 65000
        
        return features
    
    def train_model(self, features):
        """Train Isolation Forest model"""
        try:
            # Handle missing values
            features = features.fillna(features.mean())
            
            # Scale features
            features_scaled = self.scaler.fit_transform(features)
            
            # Train model
            self.iso_forest.fit(features_scaled)
            self.model_trained = True
            
            print("[+] Isolation Forest model trained successfully")
            return True
        
        except Exception as e:
            print(f"[-] Error training model: {e}")
            return False
    
    def predict_anomalies(self, features, ip_df):
        """Predict anomalies"""
        if not self.model_trained:
            print("[-] Model not trained yet")
            return None
        
        try:
            # Handle missing values
            features = features.fillna(features.mean())
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Predict anomalies (-1 for anomalies, 1 for normal)
            predictions = self.iso_forest.predict(features_scaled)
            anomaly_scores = self.iso_forest.score_samples(features_scaled)
            
            # Create results dataframe
            results = pd.DataFrame({
                'src_ip': ip_df['src_ip'],
                'dst_ip': ip_df['dst_ip'],
                'timestamp': ip_df['timestamp'],
                'is_anomaly': predictions == -1,
                'anomaly_score': anomaly_scores,
                'packet_length': ip_df['packet_length'],
                'ttl': ip_df['ttl'],
                'protocol': ip_df['protocol']
            })
            
            # Separate anomalies and normal traffic
            self.anomalies = results[results['is_anomaly'] == True]
            self.normal_traffic = results[results['is_anomaly'] == False]
            
            return results
        
        except Exception as e:
            print(f"[-] Error predicting anomalies: {e}")
            return None
    
    def analyze_dns_data(self, dns_df):
        """Analyze DNS data for anomalies"""
        try:
            anomalies = []
            
            # Parse DNS questions
            for idx, row in dns_df.iterrows():
                questions = json.loads(row['questions'])
                
                for q in questions:
                    domain = q['domain']
                    
                    # Check for suspicious domains
                    suspicious_indicators = [
                        'malware' in domain.lower(),
                        'c2' in domain.lower(),
                        'botnet' in domain.lower(),
                        len(domain) > 50,  # Unusually long domain
                        domain.count('-') > 3,  # Many hyphens
                        domain.count('_') > 2,  # Many underscores
                    ]
                    
                    if any(suspicious_indicators):
                        anomalies.append({
                            'timestamp': row['timestamp'],
                            'domain': domain,
                            'is_response': row['is_response'],
                            'reason': 'Suspicious domain characteristics'
                        })
            
            return pd.DataFrame(anomalies) if anomalies else pd.DataFrame()
        
        except Exception as e:
            print(f"[-] Error analyzing DNS data: {e}")
            return pd.DataFrame()
    
    def save_results(self, results, output_dir="anomaly_results"):
        """Save anomaly detection results"""
        try:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Save all results
            results_path = os.path.join(output_dir, "anomaly_predictions.csv")
            results.to_csv(results_path, index=False)
            print(f"[+] Saved predictions to {results_path}")
            
            # Save anomalies
            if len(self.anomalies) > 0:
                anomalies_path = os.path.join(output_dir, "detected_anomalies.csv")
                self.anomalies.to_csv(anomalies_path, index=False)
                print(f"[+] Saved anomalies to {anomalies_path}")
            
            # Save statistics
            stats = {
                "total_samples": len(results),
                "anomalies_detected": len(self.anomalies),
                "normal_traffic": len(self.normal_traffic),
                "anomaly_percentage": (len(self.anomalies) / len(results) * 100) if len(results) > 0 else 0,
                "detection_time": datetime.now().isoformat()
            }
            
            stats_path = os.path.join(output_dir, "detection_statistics.json")
            with open(stats_path, 'w') as f:
                json.dump(stats, f, indent=2)
            
            print(f"[+] Saved statistics to {stats_path}")
            return output_dir
        
        except Exception as e:
            print(f"[-] Error saving results: {e}")
            return None
    
    def print_report(self):
        """Print detailed anomaly report"""
        print("\n" + "="*70)
        print("ANOMALY DETECTION REPORT")
        print("="*70)
        
        total = len(self.anomalies) + len(self.normal_traffic)
        anomaly_percentage = (len(self.anomalies) / total * 100) if total > 0 else 0
        
        print(f"Total Samples: {total}")
        print(f"Anomalies Detected: {len(self.anomalies)} ({anomaly_percentage:.2f}%)")
        print(f"Normal Traffic: {len(self.normal_traffic)} ({100-anomaly_percentage:.2f}%)")
        
        if len(self.anomalies) > 0:
            print("\n" + "-"*70)
            print("TOP 10 MOST ANOMALOUS CONNECTIONS:")
            print("-"*70)
            
            top_anomalies = self.anomalies.nsmallest(10, 'anomaly_score')
            for idx, row in top_anomalies.iterrows():
                print(f"  {row['src_ip']:15} -> {row['dst_ip']:15} | Score: {row['anomaly_score']:8.4f} | TTL: {row['ttl']}")
        
        print("\n" + "="*70)


def main():
    """Main execution"""
    import sys
    
    # Input paths
    ip_data_path = "captured_data/ip_data.csv"
    dns_data_path = "captured_data/dns_data.csv"
    
    if len(sys.argv) > 1:
        ip_data_path = sys.argv[1]
    
    # Check if data files exist
    if not os.path.exists(ip_data_path):
        print(f"[-] IP data not found at {ip_data_path}")
        print("[*] Please run network_packet_capture.py first")
        return
    
    print("[+] Starting Network Anomaly Detection")
    print("="*70)
    
    # Initialize detector
    detector = NetworkAnomalyDetector(contamination=0.1)
    
    # Load data
    ip_df = detector.load_ip_data(ip_data_path)
    
    if ip_df is None or len(ip_df) == 0:
        print("[-] No IP data to analyze")
        return
    
    # Extract features
    features = detector.extract_features(ip_df)
    print(f"[+] Extracted {len(features.columns)} features")
    
    # Train model
    if not detector.train_model(features):
        print("[-] Failed to train model")
        return
    
    # Predict anomalies
    results = detector.predict_anomalies(features, ip_df)
    
    if results is None:
        print("[-] Failed to detect anomalies")
        return
    
    # Analyze DNS data if available
    if os.path.exists(dns_data_path):
        dns_df = detector.load_dns_data(dns_data_path)
        if dns_df is not None:
            dns_anomalies = detector.analyze_dns_data(dns_df)
            print(f"[+] DNS anomalies detected: {len(dns_anomalies)}")
    
    # Save results
    detector.save_results(results)
    
    # Print report
    detector.print_report()


if __name__ == "__main__":
    main()
