#!/bin/bash
set -e
cd "$(dirname "$0")/.."
git filter-branch -f --msg-filter "sed '/^Co-authored-by: Cursor/d'" -- --all
for ref in $(git for-each-ref --format='%(refname)' refs/original/ 2>/dev/null); do
  git update-ref -d "$ref" 2>/dev/null || true
done
git reflog expire --expire=now --all
git gc --prune=now --quiet
