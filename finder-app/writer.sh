#!/bin/sh

# Required arguments:
# 1. writefile - full path to the file to be created/written
# 2. writestr - text string to write into the file

# Check if the required number of arguments were specified
if [ "$#" -ne 2 ]; then
    echo "Error: Two arguments are required."
    echo "Usage: $0 <writefile> <writestr>"
    exit 1
fi

writefile=$1
writestr=$2

# Create the directory path if it does not exist
# dirname "$writefile" extracts the directory part of the full path
# -p ensures parent directories are created if necessary, and suppresses errors if the directory already exists
dirpath=$(dirname "$writefile")
mkdir -p "$dirpath"

# Write the content (writestr) to the file (writefile), overwriting any existing content.
# Using > for redirection will create the file if it doesn't exist.
echo "$writestr" > "$writefile"

# Check the return value of the previous command (echo/redirection)
if [ $? -ne 0 ]; then
    echo "Error: Could not create file '$writefile'."
    exit 1
fi

# Exit successfully
exit 0
