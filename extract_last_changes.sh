#!/bin/bash

# Check if CHANGES.md exists
if [ ! -f "CHANGES.md" ]; then
    echo "CHANGES.md not found."
    exit 1
fi

# Extract the changes for the most recent tag
# - The most recent tag should be the first header in CHANGES.md
# - Find the first line that starts with "## " (a tag header), and then extract all the lines below it until the next tag header or end of file

awk '
/^## / {if (p) exit; p=1; print $0; next} 
p' CHANGES.md | sed -e "s,##,Release:,g" 2>&1 1>& LAST_CHANGES.md

