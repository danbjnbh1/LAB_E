#!/bin/bash
# Dev environment launcher for Lab A

# Build image if not exists
if ! docker images | grep -q "^lab-a "; then
    echo "🔨 Building Docker image..."
    docker build --platform linux/386 -t lab-a -f dockerfile .
fi

# Run container
echo "🚀 Starting Linux x86 environment..."
docker run --platform linux/386 -it --rm \
    -v "$(pwd):/lab" \
    -w /lab \
    lab-a \
    bash

