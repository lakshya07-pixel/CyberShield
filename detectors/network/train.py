import os
import sys

# Ensure the root of the project is in the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from run import load_config, run

def main():
    """
    Clean training entry point for the Network IDS module.
    Reuses the existing research pipeline but saves the necessary feature 
    metadata alongside the baseline model artifacts for robust inference.
    """
    print("Initializing Network IDS training pipeline...")
    
    # Load configuration
    cfg = load_config("configs/config.yaml")
    
    # Ensure baseline config is enforced for the standard module
    cfg["model"]["name"] = "random_forest"
    cfg["output"]["models_dir"] = "models/network_ids/baseline_model"
    use_smote = cfg["preprocessing"].get("use_smote", True)
    
    print(f"Target models directory: {cfg['output']['models_dir']}")
    
    # Run the core training logic (which handles data, splitting, CV, saving model, and saving features)
    metrics = run(cfg, model_name=cfg["model"]["name"], use_smote=use_smote)
    
    print("\nNetwork IDS Training Complete.")
    print(f"Test Accuracy: {metrics['accuracy']:.4f}")
    print(f"Test F1 Macro: {metrics['f1_macro']:.4f}")
    print("\nModel artifacts and feature list saved to models/network_ids/baseline_model/")

if __name__ == "__main__":
    main()
