#!/bin/bash

# Get the current timestamp
timestamp=$(date +%Y-%m-%d_%H-%M-%S)

# Set up the directory name with the timestamp
directory_name="CI_Prover_Benches/$timestamp"

# Set up the full path for the directory in the home directory
directory_path="$HOME/$directory_name"

# Create the directory
mkdir -p "$directory_path"

echo "Directory '$directory_name' with timestamp '$timestamp' has been created in the home directory."

