# Save this as test_crypto.py in the project root

import pytest
import os
import time
from Cryptodome.Cipher import AES
from CyberX_2 import (
    random_multi_encrypt, 
    random_multi_decrypt, 
    derive_key, 
    entropy, 
    is_base64
)

# Mock Flask app context for DB access during testing if needed,
# but for core crypto tests, we focus on the functions themselves.

# --- 1. CORE FUNCTIONALITY TESTS ---

def test_encrypt_decrypt_integrity():
    """Test that encryption followed by decryption returns original plaintext."""
    plaintext = "The quick brown fox jumps over the lazy dog. 12345"
    
    # Run multiple times to test various randomized layers
    for _ in range(5): 
        ciphertext, infos = random_multi_encrypt(plaintext)
        
        # Check that modern cipher was applied (ciphertext must be Base64-like)
        assert is_base64(ciphertext) is True, "Final ciphertext must be Base64 encoded."
        
        # Decryption requires serialization/deserialization as it mimics DB storage
        from CyberX_2 import serialize_info, deserialize_info
        infos_json = serialize_info(infos)
        
        decrypted_text = random_multi_decrypt(ciphertext, infos_json)
        
        assert decrypted_text == plaintext, f"Decryption failed: expected '{plaintext}', got '{decrypted_text}'"

def test_derived_key_determinism():
    """Test that PBKDF2 derives the same key from the same inputs."""
    master_seed = os.urandom(32)
    purpose = "Vigenere_KEY"
    length = 10
    
    key1 = derive_key(master_seed, purpose, length)
    key2 = derive_key(master_seed, purpose, length)
    
    assert key1 == key2, "PBKDF2 derivation must be deterministic."
    
    # Test non-determinism with different purpose (salt)
    key3 = derive_key(master_seed, "Caesar_KEY", length)
    assert key1 != key3, "Keys derived from different salts must be different."


# --- 2. SECURITY CONSTRAINTS TESTS ---

def test_entropy_of_ciphertext():
    """Verify that the final ciphertext has high entropy (looks random)."""
    plaintext = "A" * 100 # Low entropy input
    ciphertext, _ = random_multi_encrypt(plaintext)
    
    ent = entropy(ciphertext)
    
    # Check if entropy is close to max (8.0 for byte-level entropy)
    assert ent > 5.0, f"Ciphertext entropy is too low ({ent}), indicating weak randomization."


# --- 3. AUDIT TESTS (Simple Attack Simulation Check) ---

# Note: The actual full attack simulation logic is complex, this test focuses 
# on ensuring the modern ciphers are not broken by simple frequency analysis.
def test_modern_cipher_resilience():
    """Test AES resilience by checking that a known-key AES output has high entropy."""
    key = os.urandom(16)
    cipher = AES.new(key, AES.MODE_ECB) # Use ECB for predictable input, though system uses CBC
    plaintext = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    
    # Use a secure cipher, but manually check the result
    encrypted_bytes = cipher.encrypt(plaintext.encode('latin-1'))
    encrypted_text = encrypted_bytes.decode('latin-1')
    
    # The output of AES (even ECB) should be random
    ent = entropy(encrypted_text)
    
    assert ent > 7.0, f"AES output entropy is too low ({ent})."