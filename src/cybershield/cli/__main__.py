"""
Main executable entrypoint for CyberShield CLI.
Usage:
    python -m src.cybershield.cli [args]
"""
import sys
from .main import main

if __name__ == "__main__":
    sys.exit(main())
