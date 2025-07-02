# Use Node.js 18 as base
FROM node:18-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    pkg-config \
    libssl-dev \
    python3 \
    python3-pip \
    jq \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install snarkjs globally
RUN npm install -g snarkjs

# Install circom
RUN git clone https://github.com/iden3/circom.git && \
    cd circom && \
    cargo build --release && \
    cargo install --path circom && \
    cd .. && rm -rf circom

# Create app directory
WORKDIR /app

# Copy package files first (for better caching)
COPY package*.json ./

# Install Node.js dependencies
RUN npm install

# Copy Rust project files
COPY evolvingDKG/Cargo.toml evolvingDKG/Cargo.lock ./evolvingDKG/

# Create build directories and src structure
RUN mkdir -p build evolvingDKG/build evolvingDKG/src

# Copy source files
COPY evolvingDKG/src/ ./evolvingDKG/src/
COPY circuits/ ./circuits/
COPY scripts/ ./scripts/

# Build Rust dependencies first (for better caching)
WORKDIR /app/evolvingDKG
RUN echo "=== Initial Rust build ===" && \
    ls -la && \
    echo "=== Checking Cargo.toml ===" && \
    cat Cargo.toml && \
    echo "=== Building dependencies ===" && \
    cargo build --release --verbose

# Return to main directory
WORKDIR /app

# Copy remaining files
COPY . .
RUN echo "=== Files copied, checking structure ===" && \
    ls -la && \
    echo "=== evolvingDKG directory ===" && \
    ls -la evolvingDKG/

# Ensure build directories exist
RUN mkdir -p build evolvingDKG/build

# Copy pre-built circuits and build artifacts (since we're containerizing existing work)
COPY build/ ./build/
COPY evolvingDKG/build/ ./evolvingDKG/build/
RUN echo "=== Build artifacts copied ===" && \
    echo "Main build directory:" && \
    ls -la build/ && \
    echo "Rust build directory:" && \
    ls -la evolvingDKG/build/

# If circuits need compilation, uncomment these lines:
# RUN npm run compile-all && npm run compile-all-rust
# RUN node -e "const CircuitSetup = require('./scripts/circuits/setup.js'); new CircuitSetup('./evolvingDKG/build').setupAll();"

# Run Rust build again to include any generated files
WORKDIR /app/evolvingDKG
RUN echo "=== Building Rust project ===" && \
    ls -la && \
    echo "=== Cargo.toml contents ===" && \
    head -20 Cargo.toml && \
    echo "=== Running cargo build --release --verbose ===" && \
    cargo build --release --verbose

# Set working directory back to root
WORKDIR /app

# Create volumes for persistent data
VOLUME ["/app/build", "/app/evolvingDKG/build"]

# Expose ports if needed
EXPOSE 3000 8080

# Set the default command to run tests with verbose output
CMD ["bash", "-c", "echo '=== Running Node.js tests ===' && npm test || echo 'Node tests not implemented' && echo '=== Running Rust tests ===' && cd evolvingDKG && cargo test --verbose"] 