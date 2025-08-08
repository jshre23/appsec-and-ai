# Proxy imports from the main middleware10.py for integrations
from pathlib import Path
import sys

# Add the parent directory to sys.path so we can import the main middleware10.py
main_dir = Path(__file__).resolve().parent.parent
if str(main_dir) not in sys.path:
    sys.path.insert(0, str(main_dir))

from middleware10 import *
