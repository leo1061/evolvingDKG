# Setup Guide

## Prerequisites Installation

### 1. Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. Install Node.js
```bash
# Using nvm (recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install node
nvm use node
```

### 3. Install Circom
```bash
# Install circom compiler
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom
```

## Project Setup

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/evolvingDKG.git
cd evolvingDKG
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Build Rust Components
```bash
cd rust-keygen
cargo build --release
```

### 4. Run Demo
```bash
./scripts/demo.sh
```

## Troubleshooting

### Common Issues

**Circom not found**:
- Ensure circom is in your PATH
- Try: `which circom`

**Rust compilation errors**:
- Update Rust: `rustup update`
- Check cargo version: `cargo --version`

**Node.js issues**:
- Clear npm cache: `npm cache clean --force`
- Delete node_modules and reinstall
