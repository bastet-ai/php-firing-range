"""Shim: phpbleed-bastet.py's wpdump/wpprofile modes -> scripts/wpbleed.py."""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
wpbleed = importlib.import_module("wpbleed")
