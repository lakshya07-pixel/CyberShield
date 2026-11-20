"""
Main executable entrypoint for Bharat AI-SoC.
Usage:
    python -m src.bharat_ai_soc [args]
"""
import sys
from .cli.main import main

if __name__ == "__main__":
    sys.exit(main())

