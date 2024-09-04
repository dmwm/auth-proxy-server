#!/bin/bash

# Check if there are any tags in the repository
if [ -z "$(git tag)" ]; then
    echo "No tags found in the repository."
    exit 1
fi

# Get all tags and sort them in descending order
tags=($(git tag --sort=-version:refname))

# Create or clear the CHANGES.md file
echo "# Changelog" > CHANGES.md

# Iterate over pairs of tags in reverse order
for ((i=0; i<${#tags[@]}-1; i++)); do
    newer_tag=${tags[i]}
    older_tag=${tags[i+1]}

    echo -e "\n## ${newer_tag}" >> CHANGES.md
    echo "" >> CHANGES.md

    # Get the list of commits between the two tags
    commits=$(git log --oneline "${older_tag}..${newer_tag}")

    # If there are no commits, mention that
    if [ -z "$commits" ]; then
        echo "* No changes" >> CHANGES.md
    else
        # Add each commit as an item in the list
        while IFS= read -r commit; do
            echo "* ${commit}" >> CHANGES.md
        done <<< "$commits"
    fi
done

echo "CHANGES.md has been generated."

