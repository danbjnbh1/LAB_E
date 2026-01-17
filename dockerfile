FROM --platform=linux/i386 i386/ubuntu:20.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install required tools
RUN apt-get update && apt-get install -y \
    gcc \
    gcc-multilib \
    nasm \
    make \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /lab

# Keep container running
CMD ["sleep", "infinity"]