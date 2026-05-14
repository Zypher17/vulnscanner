"""
Wrapper for global execution.
"""
import asyncio
import sys
import os
from scanner.main import main

if __name__ == "__main__":
    # Ensure the root of the project is in path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    asyncio.run(main())
