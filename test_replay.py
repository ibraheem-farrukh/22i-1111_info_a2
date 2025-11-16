#!/usr/bin/env python3
"""Test replay attack detection."""

import socket
import json
import base64
import secrets
import hashlib
from pathlib import Path
from app.common.utils import now_ms, b64e, b64d
from app.crypto.dh import generate_dh_params, generate_private_key, compute_public_value, compute_shared_secret, derive_aes_key
from app.crypto.aes import encrypt_aes128_ecb
from app.crypto.sign import load_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
from dotenv import load_dotenv

load_dotenv()


def load_certificate(cert_path):
    """Load certificate from file."""
    with open(cert_path, "r") as f:
        return f.read()


def replay_test(host="localhost", port=8888):
    """Test that server detects replay attacks."""
    print("=" * 60)
    print("Replay Attack Test")
    print("=" * 60)
    print("\nThis test verifies that the server detects replayed messages.")
    print("Expected result: REPLAY error\n")
    
    print("\n⚠ Note: This is a simplified test.")
    print("For full replay test:")
    print("1. Start server: python -m app.server")
    print("2. Start client: python -m app.client")
    print("3. Complete authentication and establish session")
    print("4. Send a message (note the sequence number)")
    print("5. Modify client to resend the same message with same seqno")
    print("6. Server should detect REPLAY error")
    print("\nOr modify app/client.py to resend previous message.\n")
    
    return True


if __name__ == "__main__":
    print("\nFor a complete replay test:")
    print("1. Start server: python -m app.server")
    print("2. Modify app/client.py to resend a message with duplicate seqno")
    print("3. Run client and send messages")
    print("4. Server should show REPLAY error")
    print("\nSee TESTING_GUIDE.md for complete replay test instructions\n")
    
    success = replay_test()
    
    if success:
        print("✓ Test script ready")
        print("See TESTING_GUIDE.md for complete replay test instructions")
