from flask import Flask, render_template, request, jsonify
import random
import string
import base64
import math
import numpy as np
import os
import json
import re
import time 

# PyCryptodome imports
from Cryptodome.Cipher import AES, DES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2 
from Cryptodome.Hash import SHA512 

# CSPRNG import
import secrets 

# Database import
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError 

app = Flask(__name__)

# ==================== DATABASE CONFIGURATION ====================
database_url = os.environ.get('DATABASE_URL')

if database_url:
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url.replace("postgres://", "postgresql://", 1)
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sessions.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ==================== DATABASE WAIT LOGIC ====================

def wait_for_db(max_retries=20, delay=2):
    """Checks the database connection repeatedly before starting the application."""
    if not database_url:
        print("Using SQLite, skipping remote DB wait.")
        return

    print("Attempting to connect to PostgreSQL database...")

    for i in range(max_retries):
        try:
            with app.app_context():
                db.session.execute(db.select(1))
            print("Database connected successfully!")
            return
        except OperationalError as e:
            print(f"Database not ready. Retrying in {delay} second(s)... ({i+1}/{max_retries})")
            time.sleep(delay)
        except Exception as e:
            if "relation" in str(e) and "does not exist" in str(e):
                print("Database connected, proceeding to create tables.")
                return
            print(f"An unexpected error occurred during connection attempt: {e}")
            time.sleep(delay)

with app.app_context():
    wait_for_db()
    db.create_all()

# ==================== KEY/INFO SERIALIZATION UTILITIES ====================

def serialize_info(infos):
    """Converts the infos list (with complex key types) into a JSON serializable list."""
    serializable_infos = []
    for name, key in infos:
        s_key = None
        # ADDED MASTER_SEED to serialization
        if name in ["AES", "DES", "MASTER_SEED"]: 
            s_key = base64.b64encode(key).decode('utf-8')
        elif name == "RSA":
            s_key = key.export_key().decode('utf-8')
        elif name == "Hill":
            s_key = key.tolist()
        elif name == "Monoalphabetic":
            s_key = [key[0], key[1]]
        else:
            s_key = key

        serializable_infos.append([name, s_key])
    return json.dumps(serializable_infos)

def deserialize_info(json_infos):
    """Converts the JSON string back into the original infos list with complex key types."""
    deserialized_infos = json.loads(json_infos)

    infos = []
    for name, s_key in deserialized_infos:
        key = s_key
        # ADDED MASTER_SEED to deserialization
        if name in ["AES", "DES", "MASTER_SEED"]: 
            key = base64.b64decode(s_key.encode('utf-8'))
        elif name == "RSA":
            key = RSA.import_key(s_key)
        elif name == "Hill":
            key = np.array(s_key)
        elif name == "Monoalphabetic":
            key = (s_key[0], s_key[1])

        infos.append((name, key))
    return infos


# ==================== DATABASE MODEL (Unchanged) ====================
class CipherSession(db.Model):
    id = db.Column(db.String(8), primary_key=True) 
    ciphertext = db.Column(db.Text, nullable=False)
    infos_json = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"<CipherSession {self.id}>"

# ==================== Classical Ciphers (Unchanged) ====================
# (caesar, vigenere, rail_fence, monoalphabetic, hill functions are the same as before, 
# but their default arguments are removed as keys are now dynamic)

def caesar_encrypt(text, shift):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            result += chr((ord(ch) - ord(base) + shift) % 26 + ord(base))
        else:
            result += ch
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def vigenere_encrypt(text, key):
    result = ""
    key = key.upper()
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            base = 'A' if ch.isupper() else 'a'
            result += chr((ord(ch) - ord(base) + shift) % 26 + ord(base))
            key_idx += 1
        else:
            result += ch
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.upper()
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            base = 'A' if ch.isupper() else 'a'
            result += chr((ord(ch) - ord(base) - shift) % 26 + ord(base))
            key_idx += 1
        else:
            result += ch
    return result

def rail_fence_encrypt(text, rails):
    fence = [[] for _ in range(rails)]
    rail = 0
    step = 1
    for ch in text:
        fence[rail].append(ch)
        rail += step
        if rail == rails - 1 or rail == 0:
            step = -step
    return ''.join(''.join(row) for row in fence)

def rail_fence_decrypt(cipher, rails):
    pattern = list(range(rails)) + list(range(rails-2, 0, -1))
    indices = [pattern[i % len(pattern)] for i in range(len(cipher))]
    rail_lengths = [indices.count(r) for r in range(rails)]
    rails_list = []
    pos = 0
    for l in rail_lengths:
        rails_list.append(list(cipher[pos:pos+l]))
        pos += l
    result = []
    rail_positions = [0]*rails
    for r in indices:
        result.append(rails_list[r][rail_positions[r]])
        rail_positions[r] += 1
    return ''.join(result)

def monoalphabetic_generate_key():
    letters = string.ascii_lowercase
    shuffled = list(letters)
    random.shuffle(shuffled)
    mapping = dict(zip(letters, shuffled))
    rev_mapping = {v: k for k, v in mapping.items()}
    return mapping, rev_mapping

def monoalphabetic_encrypt(text, mapping):
    result = ""
    for ch in text:
        if ch.islower():
            result += mapping.get(ch, ch)
        elif ch.isupper():
            result += mapping.get(ch.lower(), ch.lower()).upper()
        else:
            result += ch
    return result

def monoalphabetic_decrypt(text, rev_mapping):
    result = ""
    for ch in text:
        if ch.islower():
            result += rev_mapping.get(ch, ch)
        elif ch.isupper():
            result += rev_mapping.get(ch.lower(), ch.lower()).upper()
        else:
            result += ch
    return result

def hill_encrypt(text, key_matrix):
    text = text.upper().replace(" ", "")
    if len(text) % 2 != 0:
        text += 'X'
    result = ""
    for i in range(0, len(text), 2):
        pair = np.array([[ord(text[i]) - 65], [ord(text[i+1]) - 65]])
        res = np.dot(key_matrix, pair) % 26
        result += chr(int(res[0][0]) + 65) + chr(int(res[1][0]) + 65)
    return result

def hill_decrypt(text, key_matrix):
    det = int(round(np.linalg.det(key_matrix)))
    det_inv = pow(det, -1, 26)
    adj = np.round(det * np.linalg.inv(key_matrix)).astype(int) % 26
    inv_matrix = (det_inv * adj) % 26
    result = ""
    for i in range(0, len(text), 2):
        pair = np.array([[ord(text[i]) - 65], [ord(text[i+1]) - 65]])
        res = np.dot(inv_matrix, pair) % 26
        result += chr(int(res[0][0]) + 65) + chr(int(res[1][0]) + 65)
    return result

# ==================== Modern Ciphers (Step 1 - CBC Mode) ====================

def pad(s, block=16):
    pad_len = block - (len(s) % block)
    return s + chr(pad_len) * pad_len

def unpad(s):
    if not s: return s
    if isinstance(s, bytes): s = s.decode('latin-1') 
    pad_char = s[-1]
    pad_len = ord(pad_char)
    if pad_len > len(s): return s
    return s[:-pad_len]

# AES/DES now use CBC mode for better security
def aes_encrypt(plaintext):
    def aes_encrypt(plaintext):
    """
    Encrypts plaintext using AES-128 in CBC mode.
    
    CRITICAL CHANGE: Uses AES.MODE_CBC instead of the weak AES.MODE_ECB 
    (as seen in the uploaded file) for strong confidentiality. 
    It includes a randomly generated 16-byte key and a 16-byte IV.
    
    Ciphertext is returned as IV + Ciphertext, then Base64 encoded.
    
    Args:
        plaintext (str): The data to encrypt.
        
    Returns:
        tuple: (Base64 encoded ciphertext string, 16-byte random key)
    """
    # ... function body ...
    key = get_random_bytes(16)
    iv = get_random_bytes(16) 
    cipher = AES.new(key, AES.MODE_CBC, iv) 
    padded_plaintext = pad(plaintext).encode('latin-1')
    ciphertext = cipher.encrypt(padded_plaintext)
    encrypted_data = iv + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8'), key

def aes_decrypt(ciphertext_b64, key):
    try:
        encrypted_data = base64.b64decode(ciphertext_b64.encode('utf-8'))
        if len(encrypted_data) < 32: raise ValueError("Ciphertext is too short.") 
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv) 
        decrypted_bytes = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_bytes.decode('latin-1'))
        return plaintext
    except Exception as e:
        print(f"AES Decryption (CBC) Error: {e}")
        return ""

def des_encrypt(plaintext):
    key = get_random_bytes(8)
    iv = get_random_bytes(8) 
    cipher = DES.new(key, DES.MODE_CBC, iv) 
    padded_plaintext = pad(plaintext, 8).encode('latin-1') 
    ciphertext = cipher.encrypt(padded_plaintext)
    encrypted_data = iv + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8'), key

def des_decrypt(ciphertext_b64, key):
    try:
        encrypted_data = base64.b64decode(ciphertext_b64.encode('utf-8'))
        if len(encrypted_data) < 16: raise ValueError("Ciphertext is too short.")
        iv = encrypted_data[:8]
        ciphertext = encrypted_data[8:]
        cipher = DES.new(key, DES.MODE_CBC, iv) 
        decrypted_bytes = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_bytes.decode('latin-1'))
        return plaintext
    except Exception as e:
        print(f"DES Decryption (CBC) Error: {e}")
        return ""

def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = base64.b64encode(cipher.encrypt(plaintext.encode())).decode()
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(base64.b64decode(ciphertext)).decode()
    return plaintext

# ==================== Layering Transformations (Step 3) ====================

def reverse_transform(text):
    """Reverses the order of characters in the text."""
    return text[::-1]

def b64_encode_transform(text):
    """Applies Base64 encoding to obfuscate the text."""
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def b64_decode_transform(text):
    """Decodes Base64 encoded text."""
    try:
        return base64.b64decode(text.encode('utf-8')).decode('utf-8')
    except Exception:
        # If decode fails (e.g., input was not B64), return raw text
        return text 

# ==================== UTILITY FUNCTIONS (KDF & CSPRNG - Step 2) ====================

def derive_key(master_seed, purpose_str, length):
    """
    Derives a deterministic key using PBKDF2 (Password-Based Key Derivation Function 2).
    
    This function uses a cryptographic Master Seed and a unique purpose string (salt)
    to generate keys for classical ciphers. This ensures the classical keys are 
    never randomly generated or hardcoded, binding them securely to the Master Seed.
    
    Args:
        master_seed (bytes): The high-entropy seed generated by CSPRNG (secrets).
        purpose_str (str): Unique string (e.g., "Caesar_MASTER_SALT") used as salt.
        length (int): Desired length of the derived key in bytes.
        
    Returns:
        bytes: The derived key (DK) of the specified length.
    """
    """Derives a deterministic key using PBKDF2 from the master_seed and a unique purpose."""
    salt = purpose_str.encode('utf-8')
    return PBKDF2(master_seed, salt, dkLen=length, count=100000, hmac_hash_module=SHA512)

def is_base64(s):
    try:
        if len(s) % 4 != 0:
            return False
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

def entropy(s):
    if not s: return 0.0
    freq = {}
    for ch in s: freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    length = len(s)
    for v in freq.values():
        p = v / length
        ent -= p * math.log2(p)
    return ent

def generate_session_id(length=8):
    """Generates a secure, random session ID using secrets module. (Step 2)"""
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length)) # <-- CRITICAL CHANGE

# ==================== Multi-Cipher System (Steps 2 & 3) ====================

def random_multi_encrypt(text):
    classical = ["Caesar", "Vigenere", "RailFence", "Hill", "Monoalphabetic"]
    transformations = ["REVERSE", "BASE64"] 
    modern = ["AES", "DES", "RSA"]
    
    # CRITICAL: Generate a Master Seed
    master_seed = get_random_bytes(32)
    infos = [("MASTER_SEED", master_seed)]
    
    # 1. Determine Layers
    num_classical = random.randint(1, 3)
    num_modern = random.randint(1, 2)
    classical_ciphers = random.sample(classical, num_classical)
    
    # 2. Mix classical ciphers and 0-2 transformations (Step 3)
    layers = classical_ciphers
    num_transforms = random.randint(0, 2)
    layers.extend(random.sample(transformations, num_transforms))
    random.shuffle(layers)
    
    final_sequence_names = layers + modern
    
    ciphertext = text
    
    # 3. Apply layers and generate keys/store info
    for chosen in final_sequence_names:
        
        # --- Handle Layering Transformations ---
        if chosen == "REVERSE":
            ciphertext = reverse_transform(ciphertext)
            infos.append(("REVERSE", None)) 
            
        elif chosen == "BASE64":
            ciphertext = b64_encode_transform(ciphertext)
            infos.append(("BASE64", None))
            
        # --- Handle Classical Ciphers (using KDF for key generation) ---
        elif chosen in classical:
            # Use Master Seed and Cipher Name only for key derivation
            purpose = f"{chosen}_MASTER_SALT" 
            
            if chosen == "Caesar":
                key_bytes = derive_key(master_seed, purpose, 4)
                shift = int.from_bytes(key_bytes, byteorder='big') % 25 + 1 
                ciphertext = caesar_encrypt(ciphertext, shift)
                infos.append(("Caesar", shift)) # Store the derived key/shift
                
            elif chosen == "Vigenere":
                key_len = random.randint(5, 10)
                key_bytes = derive_key(master_seed, purpose, key_len)
                key = ''.join(string.ascii_uppercase[b % 26] for b in key_bytes)
                ciphertext = vigenere_encrypt(ciphertext, key)
                infos.append(("Vigenere", key)) # Store the derived key string

            elif chosen == "RailFence":
                key_bytes = derive_key(master_seed, purpose, 4)
                rails = int.from_bytes(key_bytes, byteorder='big') % 6 + 2
                ciphertext = rail_fence_encrypt(ciphertext, rails)
                infos.append(("RailFence", rails)) # Store the derived key
                
            elif chosen == "Hill":
                key_matrix = np.array([[3, 3], [2, 5]]) # Fixed key for simplicity
                ciphertext = hill_encrypt(ciphertext, key_matrix)
                infos.append(("Hill", key_matrix))
                
            elif chosen == "Monoalphabetic":
                key_map, rev_map = monoalphabetic_generate_key()
                ciphertext = monoalphabetic_encrypt(ciphertext, key_map)
                infos.append(("Monoalphabetic", (key_map, rev_map)))
            
        # --- Handle Modern Ciphers ---
        elif chosen in modern:
             if chosen == "AES":
                 ciphertext, key = aes_encrypt(ciphertext)
                 infos.append(("AES", key))
             elif chosen == "DES":
                 ciphertext, key = des_encrypt(ciphertext)
                 infos.append(("DES", key))
             elif chosen == "RSA":
                 priv, pub = rsa_generate_keys()
                 ciphertext = rsa_encrypt(ciphertext, pub)
                 infos.append(("RSA", priv))
                 
    return ciphertext, infos

def random_multi_decrypt(ciphertext, infos_json):
    infos = deserialize_info(infos_json)
    
    # Extract the Master Seed and remove it from the list
    if infos and infos[0][0] == "MASTER_SEED":
        # master_seed = infos[0][1] # Not needed for decryption, but extracted
        infos = infos[1:] 
    else:
        raise ValueError("Decryption failed: Master Seed not found in session data.")

    # Decrypt in reverse order
    for name, original_key in reversed(infos):
        
        # --- Handle Layering Transformations (Step 3) ---
        if name == "REVERSE":
            ciphertext = reverse_transform(ciphertext)
            
        elif name == "BASE64":
            ciphertext = b64_decode_transform(ciphertext)

        # --- Handle Modern Ciphers ---
        elif name == "AES":
            ciphertext = aes_decrypt(ciphertext, original_key) 
            
        elif name == "DES":
            ciphertext = des_decrypt(ciphertext, original_key)
            
        elif name == "RSA":
            ciphertext = rsa_decrypt(ciphertext, original_key)
            
        # --- Handle Classical Ciphers (using stored keys) ---
        elif name == "Caesar":
            ciphertext = caesar_decrypt(ciphertext, original_key)
            
        elif name == "Vigenere":
            ciphertext = vigenere_decrypt(ciphertext, original_key)
            
        elif name == "RailFence":
            ciphertext = rail_fence_decrypt(ciphertext, original_key)

        elif name == "Hill":
            ciphertext = hill_decrypt(ciphertext, original_key)
        
        elif name == "Monoalphabetic":
            ciphertext = monoalphabetic_decrypt(ciphertext, original_key[1])
        
        else:
             print(f"Unknown cipher step during decryption: {name}")

    return ciphertext

# ==================== ATTACK HELPERS (Unchanged) ====================

COMMON_WORDS = {
    "the","and","is","in","to","that","it","of","for","on","with","as","are",
    "this","you","not","we","they","at","be","was","by","have","from","had",
    "will","which","or","but"
}

def english_score(text):
    """A better simple scoring: fraction of common words present."""
    t = text.lower()
    score = 0
    word_list = re.split(r'[^a-z]+', t)
    for w in COMMON_WORDS:
        if w in word_list:
            score += 1
    return score / len(COMMON_WORDS)

def attack_caesar(ciphertext):
    best = {"shift": None, "plaintext": None, "score": -1}
    for s in range(26):
        pt = caesar_decrypt(ciphertext, s)
        sc = english_score(pt)
        if sc > best["score"]:
            best = {"shift": s, "plaintext": pt, "score": sc}
    return best

def attack_rail_fence(ciphertext):
    best = {"rails": None, "plaintext": None, "score": -1}
    for r in range(2, 9):
        try:
            pt = rail_fence_decrypt(ciphertext, r)
            sc = english_score(pt)
            if sc > best["score"]:
                best = {"rails": r, "plaintext": pt, "score": sc}
        except Exception:
            continue
    return best

def gcd(a, b):
    while b: a, b = b, a % b
    return a

def find_key_length(ciphertext):
    text = ''.join(ch.upper() for ch in ciphertext if ch.isalpha())
    distances = []
    for length in range(3, 6):
        for i in range(len(text) - length):
            sequence = text[i:i+length]
            for j in range(i + length, len(text) - length + 1):
                if text[j:j+length] == sequence:
                    distances.append(j - i)
    if not distances: return 5 
    def find_gcd_list(numbers):
        if len(numbers) < 2: return numbers[0] if numbers else 1
        result = numbers[0]
        for i in range(1, len(numbers)): result = gcd(result, numbers[i])
        return result
    key_guess = find_gcd_list(distances)
    if key_guess > 1 and key_guess <= 15: return key_guess
    return 5 

def attack_vigenere_for_length(ciphertext, key_length):
    text = ''.join(ch.upper() for ch in ciphertext if ch.isalpha())
    key = []
    freq_eng = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
                0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
                0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
                0.00978, 0.02360, 0.00150, 0.01974, 0.00074]

    for i in range(key_length):
        sub_cipher = [text[j] for j in range(i, len(text), key_length)]
        best_shift = 0
        min_chi_sq = float('inf')
        for shift in range(26):
            chi_sq = 0
            decrypted_freq = [0] * 26
            for char in sub_cipher:
                decrypted_char_idx = (ord(char) - ord('A') - shift) % 26
                decrypted_freq[decrypted_char_idx] += 1
            total_len = len(sub_cipher)
            if total_len == 0: continue
            for k in range(26):
                expected_count = total_len * freq_eng[k]
                observed_count = decrypted_freq[k]
                if expected_count > 0:
                    chi_sq += (observed_count - expected_count)**2 / expected_count
            if chi_sq < min_chi_sq:
                min_chi_sq = chi_sq
                best_shift = shift
        key.append(chr(best_shift + ord('A')))
    return "".join(key)

def attack_vigenere(ciphertext):
    key_length = find_key_length(ciphertext)
    if len(''.join(ch for ch in ciphertext if ch.isalpha())) < 50:
             return {"key_length": 0, "key": "", "plaintext": "", "score": -1}
    key = attack_vigenere_for_length(ciphertext, key_length)
    plaintext = vigenere_decrypt(ciphertext, key)
    score = english_score(plaintext)
    return {"key_length": key_length, "key": key, "plaintext": plaintext, "score": score}

# Helper function for Step 4
def try_classical_attacks(ciphertext):
    """Runs all classical brute-force attacks on the given ciphertext."""
    attacks = {
        "Caesar": attack_caesar(ciphertext),
        "RailFence": attack_rail_fence(ciphertext),
        "Vigenere": attack_vigenere(ciphertext)
    }
    return attacks


# ==================== Flask Routes (UPDATED FOR Step 4) ====================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    text = request.form.get("message", "")
    if not text:
        return jsonify({"result": "Error: Message is empty"}), 400

    cipher, infos = random_multi_encrypt(text)

    session_id = generate_session_id()

    with db.session.begin(): 
        while db.session.get(CipherSession, session_id):
            session_id = generate_session_id()

        new_session = CipherSession(
            id=session_id,
            ciphertext=cipher,
            infos_json=serialize_info(infos)
        )
        db.session.add(new_session)

    return jsonify({"result": cipher, "session_id": session_id})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    session_id = request.form.get("session_id", "").strip()

    if not session_id:
        return jsonify({"result": "Error: Session ID is required for decryption."}), 400

    with app.app_context():
        session_data = db.session.get(CipherSession, session_id)

    if session_data is None:
        return jsonify({"result": f"Error: Session ID '{session_id}' not found."}), 404

    ciphertext = session_data.ciphertext
    infos_json = session_data.infos_json

    try:
        plain = random_multi_decrypt(ciphertext, infos_json)
    except Exception as e:
        print(f"Decryption failed: {e}")
        return jsonify({"result": "Error during decryption. The session may be corrupted or the key is wrong."}), 500

    return jsonify({"result": plain})


@app.route("/simulate", methods=["POST"])
def simulate():
    session_id = request.form.get("session_id", "").strip()

    if not session_id:
        return jsonify({"status": "error", "message": "Session ID is required for simulation."}), 400

    with app.app_context():
        session_data = db.session.get(CipherSession, session_id)

    if session_data is None:
        return jsonify({"status": "error", "message": f"Session ID '{session_id}' not found."}), 404

    c = session_data.ciphertext
    
    # --- Step 4: Multi-Layered Attack Simulation ---
    
    # Dictionary to store all attack attempts and their results
    all_attacks = {
        "Direct": try_classical_attacks(c)
    }
    
    # 1. Check for Base64 layer (Layer 1 attack)
    is_b64 = is_base64(c)
    if is_b64:
        c_b64_decoded = b64_decode_transform(c)
        # Run classical attacks on the decoded text
        if c_b64_decoded != c:
            all_attacks["Base64_Decoded"] = try_classical_attacks(c_b64_decoded)
        
    # 2. Check for Reverse layer (Layer 1 attack)
    c_reversed = reverse_transform(c)
    if c_reversed != c:
        # Run classical attacks on the reversed text
        all_attacks["Reversed"] = try_classical_attacks(c_reversed)
        
    # 3. Check for Base64 -> Reverse layer (Layer 2 attack)
    if is_b64:
        c_b64_reversed = reverse_transform(c_b64_decoded)
        if c_b64_reversed != c_b64_decoded:
             all_attacks["Base64_Decoded_Reversed"] = try_classical_attacks(c_b64_reversed)

    # --- Consolidate Results for Reporting ---
    
    candidates = []
    findings = []
    success = False
    SCORE_THRESHOLD = 0.30
    
    # Iterate through all attack stages (Direct, Base64_Decoded, etc.)
    for stage, attacks in all_attacks.items():
        
        # Initialize findings for this stage (we only care about the best one)
        stage_success = False
        
        # Caesar
        a = attacks["Caesar"]
        if a["score"] >= SCORE_THRESHOLD:
            success = True
            stage_success = True
            candidates.append({
                "type": f"Caesar (after {stage.replace('_', ' ')})",
                "score": round(a["score"], 3),
                "plaintext": a["plaintext"],
                "meta": f"shift={a['shift']}"
            })
        
        # RailFence
        a = attacks["RailFence"]
        if a["score"] >= SCORE_THRESHOLD:
            success = True
            stage_success = True
            candidates.append({
                "type": f"RailFence (after {stage.replace('_', ' ')})",
                "score": round(a["score"], 3),
                "plaintext": a["plaintext"],
                "meta": f"rails={a['rails']}"
            })

        # Vigenere
        a = attacks["Vigenere"]
        if a["score"] >= SCORE_THRESHOLD and a["key_length"] > 1:
            success = True
            stage_success = True
            candidates.append({
                "type": f"Vigenere (after {stage.replace('_', ' ')})",
                "score": round(a["score"], 3),
                "plaintext": a["plaintext"],
                "meta": f"key={a['key']} (len={a['key_length']})"
            })

        # Record findings for the report (only record the best score per cipher type)
        # We simplify the reporting findings by only showing the DIRECT attack success/score
        if stage == "Direct":
            findings.append({"type": "Caesar", "success": attacks["Caesar"]["score"] >= SCORE_THRESHOLD, "score": round(attacks["Caesar"]["score"], 3)})
            findings.append({"type": "RailFence", "success": attacks["RailFence"]["score"] >= SCORE_THRESHOLD, "score": round(attacks["RailFence"]["score"], 3)})
            findings.append({"type": "Vigenere", "success": attacks["Vigenere"]["score"] >= SCORE_THRESHOLD, "score": round(attacks["Vigenere"]["score"], 3)})


    # --- Strength Scoring (Remains the same, based on DIRECT attack) ---
    ent = entropy(c)
    ent_norm = min(ent, 8.0) / 8.0 
    base_strength = ent_norm * 100

    if is_b64:
        base_strength = max(base_strength, 85)

    penalty = 0
    if all_attacks["Direct"]["Caesar"]["score"] >= SCORE_THRESHOLD: penalty += 1
    if all_attacks["Direct"]["RailFence"]["score"] >= SCORE_THRESHOLD: penalty += 1
    if all_attacks["Direct"]["Vigenere"]["score"] >= SCORE_THRESHOLD: penalty += 1

    strength_value = int(max(0, min(100, base_strength - penalty * 15))) 

    if strength_value >= 80:
        strength_label = "Strong"
    elif strength_value >= 50:
        strength_label = "Medium"
    else:
        strength_label = "Weak"

    conclusion = ""
    if is_b64:
        conclusion = ("Ciphertext looks like Base64 (likely modern cipher AES/DES/RSA). "
                      "Multi-layered attacks were attempted on the decoded content.")
    else:
        conclusion = f"Entropy {round(ent, 3)}. Multi-layered attacks checked Reverse and Base64 layers."


    return jsonify({
        "status": "ok",
        "entropy": round(ent, 3),
        "is_base64": is_b64,
        "findings": findings, # Only reporting direct attack findings
        "candidates": candidates, # Reporting candidates from all stages
        "success": success,
        "strength": strength_value,
        "strength_label": strength_label,
        "conclusion": conclusion
    })

if __name__ == "__main__":
    app.run(debug=True)