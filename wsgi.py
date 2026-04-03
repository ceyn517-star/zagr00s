#!/usr/bin/python3
import sys
import os

# Add the project directory to the path
path = os.path.dirname(os.path.abspath(__file__))
if path not in sys.path:
    sys.path.insert(0, path)

# Import the Flask app
from app import app as application

# For PythonAnywhere
if __name__ == "__main__":
    application.run()
