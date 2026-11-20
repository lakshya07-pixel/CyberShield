import json

from prompt_builder import build_prompt
from inference import run_llama


with open("../samples/phishing.json", "r", encoding="utf-8") as file:
    threat = json.load(file)


prompt = build_prompt(threat)

print("=" * 50)
print("GENERATED LLAMA PROMPT")
print("=" * 50)
print(prompt)
response = run_llama(prompt)

print("\nLlama Response:")
print(response)