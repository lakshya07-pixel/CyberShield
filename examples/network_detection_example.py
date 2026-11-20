import sys
import os

# Ensure the root of the project is in the path so we can import the module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

import json
from detectors.network.inference import detect_network_threat

def main():
    print("--- Network IDS Module Example ---")
    
    # In a real scenario, this 'sample' comes from a parsed network flow (e.g. CICFlowMeter output)
    # We dynamically load the expected keys here to ensure the script runs, 
    # but normally you would just construct your feature dict directly.
    features_path = "models/network_ids/baseline_model/features.json"
    
    if not os.path.exists(features_path):
        print(f"Error: {features_path} not found.")
        print("Please train the baseline model first by running:")
        print("python -m detectors.network.train")
        return

    with open(features_path, "r") as f:
        expected_features = json.load(f)
        
    # Construct a mock sample matching the expected feature keys
    # using mostly 0s to represent a small/empty flow
    sample = {feat: 0.0 for feat in expected_features}
    
    # Tweak a few values to simulate real traffic
    if "Destination Port" in sample:
        sample["Destination Port"] = 80.0
    if "Flow Duration" in sample:
        sample["Flow Duration"] = 15000.0

    print("Submitting network flow to detector...")
    try:
        result = detect_network_threat(sample)
        print("\n--- Threat Result ---")
        print(f"Source:       {result.source}")
        print(f"Threat Type:  {result.threat_type}")
        print(f"Attack Class: {result.attack_class}")
        print(f"Severity:     {result.severity}")
        print(f"Confidence:   {result.confidence:.4f}")
        print(f"Indicators:   {result.indicators}")
    except Exception as e:
        print(f"\nInference failed: {e}")

if __name__ == "__main__":
    main()
