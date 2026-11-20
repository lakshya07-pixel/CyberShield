"""
Main executable entrypoint for Bharat AI-SoC CLI.
Usage:
    python -m src.bharat_ai_soc.cli [args]
"""
import sys
from .main import main

if __name__ == "__main__":
    sys.exit(main())

