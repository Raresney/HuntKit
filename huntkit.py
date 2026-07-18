#!/usr/bin/env python3
"""Thin launcher so you can run HuntKit without installing it:

    python3 huntkit.py doctor
    python3 huntkit.py recon example.com
"""
import sys

from huntkit.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
