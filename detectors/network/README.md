# Network Intrusion Detection Module

This module provides a reusable, standalone Network Intrusion Detection System (Network IDS) based on the CICIDS2017 dataset. It encapsulates the underlying Machine Learning model (Random Forest baseline) and exposes a simple, deterministic inference API suitable for integration into a broader cybersecurity application.

## 1. What the Module Does
It accepts network flow statistics, validates and preprocesses them, feeds them into the trained ML pipeline, and outputs a standardized `ThreatResult`. The module abstracts away all ML mechanics (model loading, feature scaling, imputation, etc.) from the end-user or parent application.

## 2. Input Format
The `detect_network_threat()` function expects a Python dictionary (or pandas Series) containing the required network feature values. The required feature keys exactly match the output of CICFlowMeter (minus the target label).

```python
sample = {
    "Destination Port": 80,
    "Flow Duration": 15000,
    ...
}
```

## 3. Model Used
- **Baseline Model:** Random Forest Classifier
- **Why?** It provides a strong, CPU-friendly baseline that is highly accurate and suitable for deployment on edge hardware (such as ARM devices) without needing GPU acceleration.

## 4. Preprocessing
All preprocessing is securely wrapped inside a `scikit-learn` Pipeline saved during training. This ensures zero data leakage and deterministic behavior during inference. The pipeline includes:
- `SimpleImputer(strategy="median")`
- `VarianceThreshold(0.01)`
- `StandardScaler()`

## 5. Output Format
The module returns a `ThreatResult` dataclass instance matching this standardized schema:

```json
{
  "source": "network",
  "threat_type": "intrusion",
  "attack_class": "Bot",
  "severity": "high",
  "confidence": 0.91,
  "indicators": [
    "Classified as Bot traffic",
    "High-confidence intrusion classification"
  ]
}
```

## 6. How to Train
Before running inference, you must train the baseline model and generate the necessary artifacts. Use the clean training entrypoint:

```bash
python -m detectors.network.train
```

This script will run the original research pipeline using the default baseline parameters and output the artifacts (`random_forest_baseline.joblib`, `label_encoder.joblib`, `features.json`) to `models/network_ids/baseline_model/`.

## 7. How to Run Inference
Once trained, inference is extremely simple:

```python
from detectors.network.inference import detect_network_threat

# Gather your network features into a dictionary
sample = {
    "Destination Port": 80,
    "Flow Duration": 1000,
    ... # include all required features
}

# Get prediction
result = detect_network_threat(sample)
print(result)
```

## 8. Example Output
Run the provided example script to see it in action:
```bash
python examples/network_detection_example.py
```

## 9. Threat Engine Integration Contract

This module is designed to integrate seamlessly into a higher-level cybersecurity Threat Engine.

### 9.1 Public API & Import
```python
from detectors.network import detect_network_threat, ThreatResult
```

### 9.2 Input Requirements
* **Type:** `Dict[str, Any]` (e.g. `Dict[str, Union[float, int]]`)
* **Features:** Exactly **79 network flow features** as specified in `models/network_ids/baseline_model/features.json`.
* **Validation:**
  - If any required feature is missing, a `ValueError("Required network feature(s) missing: [...]")` is raised.
  - If any feature cannot be converted to float, a `ValueError("Invalid value for feature: [...]")` is raised.
  - The detector enforces the exact canonical column order deterministically.

### 9.3 Output Contract (`ThreatResult`)
| Field | Type | Description | Valid Values |
| :--- | :--- | :--- | :--- |
| `source` | `str` | Subsystem identifier | `"network"` |
| `threat_type` | `str` | Coarse classification | `"normal"` or `"intrusion"` |
| `attack_class` | `str` | Fine-grained attack class | `"BENIGN"`, `"Bot"`, `"DDoS"`, `"DoS"`, `"Heartbleed"`, `"Infiltration"`, `"Patator"`, `"PortScan"`, `"Web Attack"` |
| `severity` | `str` | Risk severity rating | `"low"` (for BENIGN), `"medium"`, or `"high"` |
| `confidence` | `float` | Predicted class probability | Continuous value $[0.0, 1.0]$ |
| `indicators` | `List[str]` | Human-readable indicators | Non-empty list of descriptive strings |

### 9.4 Error Handling & Zero-Side-Effect Guarantee
* **Artifact Missing:** If the model, encoder, or feature metadata cannot be found, a descriptive `FileNotFoundError` is raised. The detector **never silently retrains** or fabricates a model during inference.
* **No Pipeline Refitting:** Preprocessing (`SimpleImputer`, `VarianceThreshold`, `StandardScaler`) executes entirely via the frozen scikit-learn pipeline fitted during training. Inference has zero side effects on pipeline states.

## 10. Network Traffic / PCAP Processing Readiness & Limitations
- **Current Input Interface:** The detector accepts pre-computed flow summary records (Dict[str, Any] with 79 numerical features).
- **Extraction Architecture Gap:** The model does not inspect single isolated packets. It relies on bidirectional statistical flow aggregations produced over entire communication conversations (forward/backward inter-arrival times, packet length statistics, window size flags, subflow metrics, and idle/active times).
- **PCAP Ingest Dependency:** Raw PCAP files must first be converted into bidirectional flow records using a flow generator such as CICFlowMeter (Java CLI) or cicflowmeter (Python). Once a PCAP is converted to flow records, each record can be passed directly to detect_network_threat(flow_dict).
- **No Heavyweight Dependencies or Synthetic Fills:** Per design rules, no incomplete or heuristic packet extractors are embedded into this module, avoiding synthetic feature fabrication.
- **Rule-based Severity:** The severity field is currently a deterministic mapping (SEVERITY_MAP).
- **Static Indicators:** The indicators field returns rule-derived descriptive strings rather than feature attribution explanations (such as SHAP values).


## 11. Flow CSV to Threats Runner
For processing flow CSVs (such as those generated from PCAP files by CICFlowMeter), an offline utility is provided:
```bash
python examples/flow_to_threats.py --csv <path_to_flow_csv> --nrows 100 --limit 10
```
- **Pipeline:** Raw flow CSV -> Header stripping & .1 duplicate removal -> TCP handshake sentinel handling (`tcp_win_seen_*`) -> Feature alignment to canonical 79 features -> `detect_network_threat()` -> Structured JSON output.
- **Safety Guarantee:** If any required flow features are missing, an informative `ValueError` is raised without fabricating synthetic values.

## 12. Offline PCAP-to-Threat Pipeline

A verified offline PCAP workflow converts raw network captures (`.pcap` / `.pcapng`) into structured `ThreatResult` JSON outputs.

### 12.1 Supported Workflow & Tools
1. **Flow Extractor:** Python `cicflowmeter` (v0.5.0) with `scapy` (v2.8.0).
   - *Why Python cicflowmeter?* Java CICFlowMeter v4 requires Java 8 and native JNI `jnetpcap.dll`, which fails on modern 64-bit Java runtimes (such as Java SE 26). The Python `cicflowmeter` package provides pure-Python flow extraction without JNI dependencies.
   - *Windows Compatibility Note:* On Windows, `AsyncSniffer(filter=...)` attempts to invoke `tcpdump.exe`. Our pipeline uses Scapy's native `PcapReader` with `FlowSession.process()`, allowing complete offline flow generation on Windows without external binaries.
2. **Schema Alignment:**
   - Translates `cicflowmeter` snake_case columns (e.g. `dst_port`, `flow_duration`, `init_fwd_win_byts`) to canonical CICIDS2017 feature headers.
   - Drops non-feature metadata (`src_ip`, `dst_ip`, `src_port`, `protocol`, `timestamp`, `Label`).
   - Automatically engineers TCP window flags (`tcp_win_seen_forward`, `tcp_win_seen_backward`) via `clean()`.
   - Strictly enforces the canonical 79 features without fabricating missing features.

### 12.2 Installation
```bash
pip install scapy==2.8.0 cicflowmeter==0.5.0
```

### 12.3 Execution Commands
**End-to-End PCAP Runner:**
```bash
python examples/pcap_to_threats.py --pcap data/pcap_samples/rsasnakeoil2.pcap --output outputs/pcap_demo/threat_results.json --flow-csv outputs/pcap_demo/extracted_flows.csv
```

**Alternative Two-Step Workflow:**
1. Extract flows from PCAP:
   ```bash
   python -c "from scapy.all import PcapReader; from cicflowmeter.flow_session import FlowSession; s = FlowSession(output_mode='csv', output='outputs/pcap_demo/extracted_flows.csv'); [s.process(p) for p in PcapReader('data/pcap_samples/rsasnakeoil2.pcap')]; s.flush_flows()"
   ```
2. Classify extracted flows:
   ```bash
   python examples/flow_to_threats.py --csv outputs/pcap_demo/extracted_flows.csv --output outputs/pcap_demo/threat_results.json
   ```

### 12.4 Demonstration Artifacts & Validation Status
- **Real Packet Captures Evaluated:**
  - `data/pcap_samples/rsasnakeoil2.pcap` (25,057 bytes, 58 packets, Wireshark HTTPS/SSL sample): Produced 2 bidirectional flows, classified as `BENIGN` / normal with 84.5% and 91.4% confidence.
  - `data/pcap_samples/tcp_traffic.pcap` (6,621 bytes, 10 packets, Tcpdump project sample): Produced 1 bidirectional flow, classified as `BENIGN` / normal with 69.3% confidence.
  - `data/pcap_samples/http_sample.pcap` (247 bytes, 1 packet, Wireshark HTTP sample): Produced 1 flow, classified as `BENIGN` / normal with 70.6% confidence.
- **Output Path:** `outputs/pcap_demo/threat_results.json`
- **Ground-Truth Evaluation:** These Wireshark/Tcpdump test captures represent normal operational network traffic (not labeled intrusion datasets). The demonstration confirms end-to-end pipeline operability (Raw PCAP -> Flow Extraction -> Feature Alignment -> Model Inference -> Valid ThreatResult JSON) rather than a benchmark detection rate experiment.
- **Blockers / Limitations:** None for offline PCAP processing. Live packet sniffing requires WinPcap/Npcap driver on Windows.
