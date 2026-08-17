#!/usr/bin/env python3
"""Launch the API Test Framework GUI."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.gui import main

if __name__ == "__main__":
    main()
