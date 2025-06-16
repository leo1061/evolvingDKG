# Use Node.js as the base image
FROM node:18

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install circom
RUN curl -Ls https://github.com/iden3/circom/releases/download/v2.1.6/circom-linux-amd64 -o /usr/local/bin/circom \
    && chmod +x /usr/local/bin/circom

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application
COPY . .

# Create build directories
RUN mkdir -p build evolvingDKG/build

# Compile circuits (both Node.js and Rust versions)
RUN npm run compile-all && npm run compile-all-rust

# Set the default command
CMD ["npm", "test"] 