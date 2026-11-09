#!/usr/bin/env python3
"""Entry point for Claude Code hooks: python3 -I <path>/z-agent-guard.py"""
import os
import sys

# -I leaves the script's directory off sys.path; the package sits next to this file
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from zag.hook import main  # noqa: E402

if __name__ == "__main__":
    main()
