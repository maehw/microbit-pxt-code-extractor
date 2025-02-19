#!/bin/bash


## Escape sequence parser. Remove trailing quotation marks and \t replace tabulator, \n replace newline-character etc.

# Help text
help_text="Usage: $0 <filename> or $0 -h for this help text.";

# Parameter checking
if [ "$1" == "-h" ]; then
  echo "$help_text";
  exit 0;
elif [ -z "$1" ]; then
  echo "$help_text";
  exit 1;
fi

# Storage filename
filename="$1";

# Check file existing
if [ ! -f "$filename" ]; then
  echo "ERROR: The '$filename' file nem not exist.";
  exit 1;
fi

# Read file content
text=$(cat "$filename");

# Remove trailing quotation marks
text="${text:1:-1}";

# Replace escape sequences
text=$(echo -e "$text");

# Replace \" with "
text="${text//\\\"/\"}";

# Write output
echo "$text";
