# 2PAKA Key Agreement Protocol using PBC Library

## Overview

This repository contains an implementation of the 2PAKA (Two-Party Authenticated Key Agreement) protocol using the PBC (Pairing-Based Cryptography) library. The 2PAKA protocol is designed for secure key exchange in identity-based IoT environments. This README provides information on prerequisites, compilation, usage, and other relevant details.

## Prerequisites

Before using this code, ensure you have the following prerequisites in place:

- **PBC Library:** The PBC library provides pairing-based cryptographic operations. To install it, follow the instructions in the [PBC Library Documentation](https://crypto.stanford.edu/pbc/download.html).
- **C Compiler:** You need a C compiler (e.g., GCC) installed on your system.

## Compilation

To compile the code, follow these steps:

1. Make sure you have the PBC library installed as per the prerequisites.
2. Open a terminal in the directory containing the code.
3. Use the following command to compile the code:

   ```sh
   gcc -o 2paka_protocol 2paka_protocol.c -L -lpbc -lgmp
   
## NOTES

1.This code is a demonstration of the 2PAKA protocol using the PBC library. It's crucial to understand the protocol's security assumptions and cryptographic library usage before applying it in real-world scenarios.
2.Familiarize yourself with PBC, elliptic curve cryptography, and the 2PAKA protocol before modifying the code for your specific needs.
3.The code assumes a symmetric pairing setting; ensure your chosen pairing parameters are symmetric.

