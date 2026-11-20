"""
Main executable entrypoint for CyberShield.
Usage:
    python -m src.cybershield [args]
"""
import sys
from .cli.main import main

if __name__ == "__main__":
    sys.exit(main())

