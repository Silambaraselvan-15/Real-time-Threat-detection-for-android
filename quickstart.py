"""
Quick Start Example - Network Packet Capture & Anomaly Detection
Run this to get started with network threat detection
"""

from network_packet_capture import NetworkPacketCapture
from network_anomaly_detector import NetworkAnomalyDetector
import os
import time

def main():
    print("\n" + "="*70)
    print("NETWORK THREAT DETECTION - QUICK START")
    print("="*70)
    
    # Step 1: Capture packets
    print("\n[STEP 1] Starting Network Packet Capture")
    print("-"*70)
    print("This will capture network traffic for 30 seconds...")
    print("Capturing: IP headers, DNS queries, and anomaly indicators")
    
    input("Press Enter to start capture... (Ctrl+C to skip)")
    
    try:
        capturer = NetworkPacketCapture(output_dir="captured_data")
        
        # Start capture for 30 seconds on all interfaces
        capturer.start_capture(
            packet_count=0,  # No limit on packet count
            timeout=30,      # 30 seconds timeout
            interface=None,  # Auto-detect interface
            filters=""       # Capture all traffic
        )
        
        # Save captured data
        capturer.save_all_data()
        
    except KeyboardInterrupt:
        print("\n[*] Capture interrupted by user")
    except PermissionError:
        print("\n[-] ERROR: This requires administrator privileges!")
        print("[*] Please run as administrator (Windows) or with sudo (Linux/Mac)")
        return
    except Exception as e:
        print(f"\n[-] Error during capture: {e}")
        return
    
    # Check if data was captured
    if not os.path.exists("captured_data/ip_data.csv"):
        print("\n[-] No data captured. Skipping analysis.")
        return
    
    # Step 2: Analyze with Isolation Forest
    print("\n[STEP 2] Anomaly Detection Analysis")
    print("-"*70)
    print("Training Isolation Forest model on captured traffic...")
    
    try:
        detector = NetworkAnomalyDetector(contamination=0.1)
        
        # Load captured data
        ip_df = detector.load_ip_data("captured_data/ip_data.csv")
        
        if ip_df is None or len(ip_df) == 0:
            print("[-] No data to analyze")
            return
        
        # Extract features
        features = detector.extract_features(ip_df)
        print(f"[+] Extracted {len(features.columns)} features from traffic")
        
        # Train model
        if detector.train_model(features):
            # Predict anomalies
            results = detector.predict_anomalies(features, ip_df)
            
            # Save results
            detector.save_results(results, output_dir="anomaly_results")
            
            # Print report
            detector.print_report()
        else:
            print("[-] Failed to train anomaly model")
    
    except Exception as e:
        print(f"[-] Error during analysis: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*70)
    print("ANALYSIS COMPLETE")
    print("="*70)
    print("\nOutput files saved to:")
    print("  - captured_data/     (raw packet data)")
    print("  - anomaly_results/   (analysis results)")
    print("\nNext steps:")
    print("  1. Review detected_anomalies.csv for suspicious connections")
    print("  2. Check anomaly_predictions.csv for anomaly scores")
    print("  3. Investigate top anomalies with lowest scores")
    print("\nRun again with different parameters to capture specific traffic")
    print("(e.g., DNS-only: python network_packet_capture.py 0 60 \"\" \"dns\")")


if __name__ == "__main__":
    main()
