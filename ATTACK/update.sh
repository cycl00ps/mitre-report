#!/bin/bash

# Navigate to the repository directory
cd "$(dirname "$0")"

echo "Starting MITRE ATT&CK data update..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Creating one..."
    python3 -m venv venv
    ./venv/bin/pip install -r requirements.txt
fi

# Run the sync script using the venv python
echo "Running sync_mitre.py..."
./venv/bin/python3 sync_mitre.py

if [ $? -eq 0 ]; then
    echo "Update successful!"
else
    echo "Update failed. Please check the error messages above."
    exit 1
fi