# Network Packet Capture & Anomaly Detection Guide

## Overview
This suite includes two scripts for network-based threat detection:
1. **network_packet_capture.py** - Captures network packets (IP & DNS)
2. **network_anomaly_detector.py** - Detects anomalies using Isolation Forest

## Installation

### Prerequisites
- Python 3.7+
- Administrator/root privileges (required for packet capture)

### Required Packages
```bash
pip install scapy pandas scikit-learn numpy
```

On Linux/Mac:
```bash
sudo pip install scapy pandas scikit-learn numpy
```

## Usage

### 1. Capture Network Packets

#### Basic capture (all traffic for 60 seconds):
```bash
python network_packet_capture.py
```

#### Custom parameters:
```bash
python network_packet_capture.py [packet_count] [timeout] [interface] [filter]
```

**Parameters:**
- `packet_count`: Number of packets to capture (0 = unlimited, default: 0)
- `timeout`: Capture duration in seconds (default: 60)
- `interface`: Network interface name (default: auto-detect)
- `filter`: BPF filter expression (default: empty/all traffic)

**Examples:**

Capture 1000 packets on default interface:
```bash
python network_packet_capture.py 1000
```

Capture DNS traffic for 120 seconds:
```bash
python network_packet_capture.py 0 120 "" "dns"
```

Capture DNS traffic on specific interface (Linux):
```bash
python network_packet_capture.py 0 60 eth0 "dns"
```

Capture TCP traffic on port 53 (DNS):
```bash
python network_packet_capture.py 0 60 "" "tcp port 53"
```

Capture UDP traffic:
```bash
python network_packet_capture.py 0 60 "" "udp"
```

### 2. Analyze Captured Data

Once packets are captured, analyze for anomalies:

```bash
python network_anomaly_detector.py
```

Or specify custom data path:
```bash
python network_anomaly_detector.py path/to/ip_data.csv
```

## Output Files

### From network_packet_capture.py (in `captured_data/` folder):
- **ip_data.csv** - All IP packet information
- **dns_data.csv** - DNS queries and responses
- **packets_data.csv** - Combined packet information
- **network_data.json** - Complete data in JSON format including statistics

### From network_anomaly_detector.py (in `anomaly_results/` folder):
- **anomaly_predictions.csv** - All packets with anomaly scores
- **detected_anomalies.csv** - Only anomalous packets
- **detection_statistics.json** - Summary statistics

## Features Extracted for Anomaly Detection

### IP-Based Features:
1. **TTL (Time To Live)** - Suspicious if < 5 or > 250
2. **Packet Length** - Suspicious if > 65000 bytes
3. **Protocol Type** - TCP, UDP, ICMP, etc.
4. **Fragmentation Status** - Whether packet is fragmented
5. **Source IP Frequency** - How often the source IP appears
6. **Destination IP Frequency** - How often the destination IP appears

### DNS-Based Indicators:
1. Domain length > 50 characters
2. Excessive hyphens (> 3)
3. Excessive underscores (> 2)
4. Suspicious keywords (malware, c2, botnet, etc.)
5. DNS query frequency per domain

## Anomaly Detection Algorithm

Uses **Isolation Forest** algorithm:
- Contamination rate: 10% (adjustable)
- 100 trees for detection
- Anomaly score range: -1 to 1 (lower = more anomalous)
- Default threshold: -0.5 (configurable)

## Interpretation

### Anomaly Score:
- Scores close to -1: Highly anomalous traffic
- Scores close to 0: Moderately suspicious
- Scores close to 1: Normal traffic

### Common Anomalies Detected:
- Unusual TTL values
- Oversized packets
- Abnormal traffic patterns per IP
- DGA (Domain Generation Algorithm) domains
- Frequent DNS queries to unusual domains
- Connection attempts to suspicious IPs

## Real-Time Monitoring

For continuous monitoring, use a bash/batch script:

### Linux/Mac:
```bash
#!/bin/bash
while true; do
    echo "Starting capture session..."
    python network_packet_capture.py 0 60  # 60-second capture
    python network_anomaly_detector.py
    echo "Anomaly detection complete. Sleeping..."
    sleep 300  # Wait 5 minutes before next capture
done
```

### Windows PowerShell:
```powershell
while ($true) {
    Write-Host "Starting capture session..."
    python network_packet_capture.py 0 60
    python network_anomaly_detector.py
    Start-Sleep -Seconds 300
}
```

## Advanced Filtering

### Capture only DNS:
```bash
python network_packet_capture.py 0 60 "" "dns"
```

### Capture only HTTP:
```bash
python network_packet_capture.py 0 60 "" "tcp port 80"
```

### Capture only HTTPS:
```bash
python network_packet_capture.py 0 60 "" "tcp port 443"
```

### Capture only traffic from specific IP:
```bash
python network_packet_capture.py 0 60 "" "src 192.168.1.100"
```

### Exclude traffic to specific IP:
```bash
python network_packet_capture.py 0 60 "" "not dst 8.8.8.8"
```

## Troubleshooting

### "PermissionError: Operation not permitted"
- **Linux/Mac**: Run with sudo: `sudo python network_packet_capture.py`
- **Windows**: Run Command Prompt as Administrator

### "No network interfaces found"
- Ensure your network adapter is active
- Try specifying interface explicitly
- Check available interfaces: `python -c "from scapy.all import get_if_list; print(get_if_list())"`

### Empty CSV files
- Capture may have timed out before catching any packets
- Try increasing timeout or using DNS filter
- Check if selected filter is too restrictive

### Low anomaly detection rate
- Adjust contamination parameter in network_anomaly_detector.py
- Increase capture time for better baseline
- Tune feature extraction thresholds

## Integration with Isolation Forest

The anomaly detector integrates with your existing Isolation Forest setup:
- Uses sklearn's IsolationForest
- Compatible with existing ml model pipeline
- Can be enhanced by combining with other detectors
- Outputs can be used for further analysis or visualization

## Security Notes

1. Requires administrative privileges for packet capture
2. May consume significant bandwidth/CPU with heavy traffic
3. Store captured data securely (contains network information)
4. Filter sensitive data before sharing results
5. Use appropriate network monitoring policies

## Performance Considerations

- Capture speed depends on network traffic volume
- CSV export may be slow with > 100K packets
- Increase contamination for faster detection on large datasets
- Use BPF filters to reduce packet volume

---

For questions or issues, check the script docstrings or logs for detailed error messages.
