import sys
import os
from scanner.main import main

if __name__ == "__main__":
    # Add current directory to path to support absolute imports
    sys.path.insert(0, os.getcwd())
    main()
