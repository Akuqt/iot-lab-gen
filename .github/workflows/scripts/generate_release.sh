#!/bin/bash
set -e

REPO="https://github.com/Akuqt/iot-lab-gen"

if [[ -z "$RELEASE_VERSION" ]]; then
    echo "RELEASE_VERSION is not set. Exiting."
    exit 1
fi

function get_version_commit() {
    local skip_count=${1:-0}
    
    if [[ "$skip_count" -eq 0 ]]; then
        git rev-parse HEAD
    else
        local tag_index=$((skip_count))
        local tag_name=$(git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+' | sed -n "${tag_index}p")
        
        if [[ -n "$tag_name" ]]; then
            git rev-list -n 1 "$tag_name"
        fi
    fi
}

function get_version() {
    local commit_sha=$1
    local tag=$(git describe --tags --exact-match "$commit_sha" 2>/dev/null)
    
    if [[ -n "$tag" ]]; then
        echo "$tag"
    else
        echo "$RELEASE_VERSION"
    fi
}

function get_commit_messages() {
    local format="Author:%an---Email:%ae---Message:%s---Long:%H---Short:%h"
    local content_flags=(--pretty="$format")
    
    git log "${content_flags[@]}" "$1".."$2" | grep -E 'feat:|fix:'
}

function process_type(){
    echo "$1" | sed "s/$2: //" | sed 's/^./\U&/'
}

function process_commit_link(){
    echo "$REPO/commit/$1"
}

function process_line(){
    echo "- [[\`$5\`]($(process_commit_link "$4"))] - **$(process_type "$3" "$6")** _by_ [$1](mailto:$2)\n"
}

function process_messages() {
    local rtitle="## IoT Lab Generator"
    local rdescription1="Infrastructure-as-Code tool for deploying realistic, virtualized IoT environments on Linux."
    local rdescription2="It allows for the simulation of diverse device personas and network traffic patterns for security testing."
    local res="$rtitle\n\n$rdescription1 $rdescription2\n\n## What's Changed\n\n"
    local features=""
    local fixes=""
    while IFS= read -r line; do
        if [[ $line == *"Author:"* ]]; then
            local author=$(echo  "$line" | awk -F'---' '{print $1}' | sed 's/Author://')
            local email=$(echo   "$line" | awk -F'---' '{print $2}' | sed 's/Email://')
            local message=$(echo "$line" | awk -F'---' '{print $3}' | sed 's/Message://')
            local long=$(echo  "$line" | awk -F'---' '{print $4}' | sed 's/Long://')
            local short=$(echo  "$line" | awk -F'---' '{print $5}' | sed 's/Short://')
            if [[ $message == *"feat:"* ]]; then
                features+=$(process_line "$author" "$email" "$message" "$long" "$short" "feat")
            fi
            if [[ $message == *"fix:"* ]]; then
                fixes+=$(process_line "$author" "$email" "$message" "$long" "$short" "fix")
            fi
        fi
    done < <(echo "$1")
    if [[ -n $features ]]; then
        res+="## New Features\n\n$features\n"
    fi
    if [[ -n $fixes ]]; then
        res+="## Fixes\n\n$fixes\n"
    fi
    res+="---\n\n"
    res+="**Full Changelog**: $REPO/compare/$2...$3\n"
    mkdir -p release_notes
    echo -e "$res" > "./release_notes/notes.md"
}

current_version_commit=$(get_version_commit 0)
last_version_commit=$(get_version_commit 1)

current_version=$(get_version "$current_version_commit")
last_version=$(get_version "$last_version_commit")

messages=$(get_commit_messages "$last_version_commit" "$current_version_commit")

process_messages "$messages" "$last_version" "$current_version"

echo "TAG_NAME=$current_version"