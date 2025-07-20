#!/bin/bash
# Run this script using `source experiments/setup.sh` to set up the environment for the experiments.

set -e  # Exit immediately if a command exits with a non-zero status.

# Check that pip is installed inside a virtual environment
if ! command -v pip &> /dev/null; then
    echo "pip is not installed. Please install pip and try again."
    exit 1
fi

# Check if the virtual environment is activated
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "No virtual environment is activated. Please activate your virtual environment before running this script."
    exit 1
fi

# Find all `requirements.txt` files in each of the subdirectories inside `dataset/`
# and install the packages listed in them.
find dataset/ -type f -name "requirements.txt" | while read -r req_file; do
    echo "Installing requirements from $req_file"
    pip install -r "$req_file"
done

# Done!
echo "Environment setup complete. All requirements installed."
