import json

from severity import calculate_severity
from rules import get_threat_explanation, get_indicator_explanation
from recommendations import get_recommendation



def generate_advisory(file_path):
    # Read threat JSON file
    with open(file_path, "r", encoding="utf-8") as file:
        threat = json.load(file)

    threat_type = threat["threat_type"]
    confidence = threat["confidence"]
    indicators = threat["indicators"]

    # Calculate severity
    severity = calculate_severity(confidence)

    # Generate rule-based explanation
    explanation = get_threat_explanation(
        threat_type,
        indicators
    )

    # Generate indicator explanations
    indicator_explanations = get_indicator_explanation(
        indicators
    )

    # Generate rule-based recommendation
    recommendation = get_recommendation(threat_type)

    # Display trusted rule-based advisory
    print("=" * 50)
    print("          CYBER AI ADVISORY")
    print("=" * 50)

    print(f"Threat Type : {threat_type}")
    print(f"Severity    : {severity.upper()}")
    print(f"Confidence  : {confidence * 100:.0f}%")

    print("\nWhy was this detected?")
    print(explanation)

    print("\nIndicators:")
    for item in indicator_explanations:
        print(f"- {item}")

    print("\nRecommended Action:")
    print(recommendation)

    # Llama output is disabled until its claims can be verified.
    print("\nExperimental Llama Explanation:")
    print("Llama output is disabled because it may contain unsupported claims.")

    print("=" * 50)

if __name__ == "__main__":
    generate_advisory("samples/intrusion.json")