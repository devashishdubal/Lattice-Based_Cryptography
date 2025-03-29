# Lattice-Based Cryptography: Client-Server Communication Model

## Overview
This project implements a secure client-server communication model using Lattice-based cryptography, specifically the Learning with Errors (LWE) problem. The system operates through a terminal-based interface.

## Features
- **Secure Communication:** Utilizes LWE for encryption and decryption.
- **Client-Server Model:** The server listens for connections while the client sends and receives encrypted messages.
- **Python Implementation:** Written in Python with appropriate cryptographic libraries.

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/devashishdubal/Lattice-Based_Cryptography.git
   cd Lattice-Based Cryptography
   ```
2. Install dependencies:
   ```sh
   pip install numpy
   ```

## Dependencies
Ensure you have the following Python libraries installed:
- `numpy`

## Usage
### Start the Server
Run the server script to begin listening for client connections:
```sh
python final_server.py
```

### Start the Client
Run the client script to connect to the server and exchange encrypted messages:
```sh
python final_client.py
```

## File Structure
- `final_server.py` - Implements the server logic, including key generation and message handling.
- `final_client.py` - Implements the client logic, including encryption and decryption of messages.

## Acknowledgments and References
- Inspired by research in post-quantum cryptography.
- Based on concepts from Lattice-based cryptography and Learning with Errors (LWE).
- https://en.wikipedia.org/wiki/Lattice-based_cryptography
- On Lattices, Learning with Errors, Random Linear Codes, and Cryptography - Oded Regev - https://arxiv.org/abs/2401.03703

