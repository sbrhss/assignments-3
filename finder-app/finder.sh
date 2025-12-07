#!/bin/sh

# Check if the required number of arguments were provided
if [ "$#" -ne 2 ]; then
  echo "Error: Two arguments are required."
  echo "Usage: $0 <filesdir> <searchstr>"
  exit 1
fi

# Assign arguments to variables for readability
filesdir=$1
searchstr=$2

# Check if filesdir is a valid directory
if [ ! -d "$filesdir" ]; then
  echo "Error: '$filesdir' is not a directory."
  echo "Usage: $0 <filesdir> <searchstr>"
  exit 1
fi

# Count the number of files and matching lines
# 1. 'find "$filesdir" -type f' lists all files (type f) recursively in filesdir.
# 2. 'wc -l' counts the total number of files (X).
# 3. 'grep -r "$searchstr" "$filesdir"' recursively searches for searchstr in all files.
# 4. '| wc -l' counts the total number of matching lines found (Y).

# Count the number of files (X) in the directory and its subdirectories
# Use -type f to ensure only files are counted, not directories or special files.
X=$(find "$filesdir" -type f | wc -l)

# Count the number of matching lines (Y) across all files
# We use 'grep -r' for recursive search.
# Note: The 'grep -r' output is piped directly to 'wc -l' to count the total lines.
Y=$(grep -r "$searchstr" "$filesdir" | wc -l)

# Print the final result message
echo "The number of files are $X and the number of matching lines are $Y"

# Exit successfully
exit 0
