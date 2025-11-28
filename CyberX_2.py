from flask import Flask, render_template, request, jsonify
import random
import string
import base64
import math
import numpy as np
import os
import json
import re
import secrets
import time
# PyCryptodome imports
from Cryptodome.Cipher import AES, DES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes # Used for CSPRNG keys/IVs
# Database import
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError

app = Flask(__name__)

# ==================== DATABASE CONFIGURATION ====================
database_url = os.environ.get('DATABASE_URL')

if database_url:
    # Production: PostgreSQL with Heroku fix
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url.replace("postgres://", "postgresql://", 1)
else:
    # Local development: SQLite
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sessions.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ==================== DATABASE WAIT LOGIC ====================

def wait_for_db(max_retries=20, delay=2):
    """
    Checks the database connection repeatedly before starting the application.
    """
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

    print("CRITICAL ERROR: Database connection failed after multiple retries. Exiting.")

# Run the database check and create tables when the app initializes (Gunicorn or Local)
with app.app_context():
    wait_for_db()
    db.create_all()

# ==================== KEY/INFO SERIALIZATION UTILITIES ====================

def serialize_info(infos):
    """Converts the infos list (with complex key types) into a JSON serializable list."""
    serializable_infos = []
    for name, key in infos:
        s_key = None
        if name in ["AES", "DES"]:
            # AES/DES key is bytes, convert to base64 string
            s_key = base64.b64encode(key).decode('utf-8')
        elif name == "RSA":
            # RSA private key object needs to be stored as a string (PEM format)
            s_key = key.export_key().decode('utf-8')
        elif name == "Hill":
            # Hill key matrix (NumPy array) needs to be converted to a list
            s_key = key.tolist()
        elif name == "Monoalphabetic":
            # Key map is a tuple (map, rev_map), convert to list of [map_dict, rev_map_dict]
            s_key = [key[0], key[1]]
        else:
            # Caesar, Vigenere, RailFence keys are simple types (int or string)
            s_key = key

        serializable_infos.append([name, s_key])
    return json.dumps(serializable_infos)

def deserialize_info(json_infos):
    """Converts the JSON string back into the original infos list with complex key types."""
    deserialized_infos = json.loads(json_infos)

    infos = []
    for name, s_key in deserialized_infos:
        key = s_key
        if name in ["AES", "DES"]:
            # Convert base64 string back to bytes
            key = base64.b64decode(s_key.encode('utf-8'))
        elif name == "RSA":
            # Convert PEM string back to RSA private key object
            key = RSA.import_key(s_key)
        elif name == "Hill":
            # Convert list back to NumPy array
            key = np.array(s_key)
        elif name == "Monoalphabetic":
            # Convert list back to tuple (map_dict, rev_map_dict)
            key = (s_key[0], s_key[1])

        infos.append((name, key))
    return infos


# ==================== DATABASE MODEL ====================
class CipherSession(db.Model):
    id = db.Column(db.String(8), primary_key=True) # The 8-char session ID
    ciphertext = db.Column(db.Text, nullable=False)
    # Store the complex 'infos' structure as a JSON string (TEXT field)
    infos_json = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"<CipherSession {self.id}>"

# ==================== Classical Ciphers ====================
# (Functions remain unchanged)

def caesar_encrypt(text, shift=3):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            result += chr((ord(ch) - ord(base) + shift) % 26 + ord(base))
        else:
            result += ch
    return result

def caesar_decrypt(text, shift=3):
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

def rail_fence_encrypt(text, rails=3):
    fence = [[] for _ in range(rails)]
    rail = 0
    step = 1
    for ch in text:
        fence[rail].append(ch)
        rail += step
        if rail == rails - 1 or rail == 0:
            step = -step
    return ''.join(''.join(row) for row in fence)

def rail_fence_decrypt(cipher, rails=3):
    # Build pattern
    pattern = list(range(rails)) + list(range(rails-2, 0, -1))
    indices = [pattern[i % len(pattern)] for i in range(len(cipher))]
    # Determine how many chars in each rail
    rail_lengths = [indices.count(r) for r in range(rails)]
    # Slice ciphertext per rail
    rails_list = []
    pos = 0
    for l in rail_lengths:
        rails_list.append(list(cipher[pos:pos+l]))
        pos += l
    # Reconstruct
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

# ==================== Modern Ciphers (UPGRADED) ====================

def pad(s, block=16):
    pad_len = block - (len(s) % block)
    # Ensure padding character is a string if s is a string
    return s + chr(pad_len) * pad_len

def unpad(s):
    if not s:
        return s
    # Ensure s is a string before checking the last character
    if isinstance(s, bytes):
        # We handle this case in AES/DES decrypt, but keeping general utility safe
        s = s.decode('latin-1') 

    pad_char = s[-1]
    pad_len = ord(pad_char)
    if pad_len > len(s):
        return s # Return original if padding looks insane

    return s[:-pad_len]

# 🟢 UPGRADED to AES.MODE_CBC
def aes_encrypt(plaintext):
    key = get_random_bytes(16)
    iv = get_random_bytes(16) # IV size must be 16 bytes for AES-CBC
    
    # Use CBC mode with the random IV
    cipher = AES.new(key, AES.MODE_CBC, iv) 
    
    # Pad and encode plaintext
    padded_plaintext = pad(plaintext).encode('latin-1')
    
    ciphertext = cipher.encrypt(padded_plaintext)
    
    # CRITICAL: Prepend IV to ciphertext before Base64 encoding
    encrypted_data = iv + ciphertext
    
    # Base64 encode the whole thing
    return base64.b64encode(encrypted_data).decode('utf-8'), key

# 🟢 UPGRADED to AES.MODE_CBC
def aes_decrypt(ciphertext_b64, key):
    try:
        # Base64 decode the IV + Ciphertext
        encrypted_data = base64.b64decode(ciphertext_b64.encode('utf-8'))
        
        # Check if the data is long enough for IV (16) + min block (16)
        if len(encrypted_data) < 32:
             raise ValueError("Ciphertext is too short.") 
             
        # Extract the IV (first 16 bytes) and the actual ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Use CBC mode with the extracted IV
        cipher = AES.new(key, AES.MODE_CBC, iv) 
        
        decrypted_bytes = cipher.decrypt(ciphertext)
        
        # Unpad and decode
        plaintext = unpad(decrypted_bytes.decode('latin-1'))
        return plaintext
    except ValueError as e:
        print(f"AES Decryption (CBC) Error: {e}")
        return ""
    except Exception as e:
        print(f"AES Decryption (CBC) Error: {e}")
        return ""

# 🟢 UPGRADED to DES.MODE_CBC
def des_encrypt(plaintext):
    key = get_random_bytes(8)
    iv = get_random_bytes(8) # IV size must be 8 bytes for DES-CBC
    
    # Use CBC mode with the random IV
    cipher = DES.new(key, DES.MODE_CBC, iv) 
    
    # Pad and encode plaintext (using block size 8)
    padded_plaintext = pad(plaintext, 8).encode('latin-1') 
    
    ciphertext = cipher.encrypt(padded_plaintext)
    
    # CRITICAL: Prepend IV to ciphertext before Base64 encoding
    encrypted_data = iv + ciphertext
    
    # Base64 encode the whole thing
    return base64.b64encode(encrypted_data).decode('utf-8'), key

# 🟢 UPGRADED to DES.MODE_CBC
def des_decrypt(ciphertext_b64, key):
    try:
        # Base64 decode the IV + Ciphertext
        encrypted_data = base64.b64decode(ciphertext_b64.encode('utf-8'))
        
        # Check if the data is long enough for IV (8) + min block (8)
        if len(encrypted_data) < 16: 
             raise ValueError("Ciphertext is too short.")
             
        # Extract the IV (first 8 bytes) and the actual ciphertext
        iv = encrypted_data[:8]
        ciphertext = encrypted_data[8:]
        
        # Use CBC mode with the extracted IV
        cipher = DES.new(key, DES.MODE_CBC, iv) 
        
        decrypted_bytes = cipher.decrypt(ciphertext)
        
        # Unpad and decode
        plaintext = unpad(decrypted_bytes.decode('latin-1'))
        return plaintext
    except ValueError as e:
        print(f"DES Decryption (CBC) Error: {e}")
        return ""
    except Exception as e:
        print(f"DES Decryption (CBC) Error: {e}")
        return ""

def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    # RSA encryption works best on chunks, but for this demo, we assume the input fits
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = base64.b64encode(cipher.encrypt(plaintext.encode())).decode()
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(base64.b64decode(ciphertext)).decode()
    return plaintext


# ==================== Multi-Cipher System (UPGRADED with KDF) ====================

def random_multi_encrypt(text):
    classical = ["Caesar", "Vigenere", "RailFence", "Hill", "Monoalphabetic"]
    modern = ["AES", "DES", "RSA"]
    
    # 🟢 CRITICAL CHANGE 1: Generate a Master Seed (32 bytes)
    master_seed = get_random_bytes(32)
    # Master seed is the ultimate secret, stored as the first item in infos
    infos = [("MASTER_SEED", master_seed)]
    
    num_classical = random.randint(1, 3)
    num_modern = random.randint(1, 2)
    classical_sequence = random.sample(classical, num_classical)
    modern_sequence = random.sample(modern, num_modern)
    
    ciphertext = text
    
    # Classical first
    for i, chosen in enumerate(classical_sequence):
        # Derive a key unique to this cipher and its position in the sequence (i)
        # 🟢 CRITICAL CHANGE 2: Use KDF for deterministic, random-looking keys
        
        purpose = f"{chosen}_KEY_{i}" # Unique identifier for salt
        
        if chosen == "Caesar":
            # Caesar shift 1-25. Derive a 4-byte key, take the first byte, and modulo 25+1
            key_bytes = derive_key(master_seed, purpose, 4)
            shift = int.from_bytes(key_bytes, byteorder='big') % 25 + 1 
            ciphertext = caesar_encrypt(ciphertext, shift)
            infos.append(("Caesar", shift))
            
        elif chosen == "Vigenere":
            # Vigenere key length 5-10. Derive a 10-byte key, convert to a word.
            key_len = random.randint(5, 10)
            key_bytes = derive_key(master_seed, purpose, key_len)
            key = ''.join(string.ascii_uppercase[b % 26] for b in key_bytes)
            ciphertext = vigenere_encrypt(ciphertext, key)
            infos.append(("Vigenere", key))
            
        elif chosen == "RailFence":
            # RailFence rails 2-7.
            key_bytes = derive_key(master_seed, purpose, 4)
            rails = int.from_bytes(key_bytes, byteorder='big') % 6 + 2
            ciphertext = rail_fence_encrypt(ciphertext, rails)
            infos.append(("RailFence", rails))
            
        elif chosen == "Hill":
            # Hill key remains fixed for now, as dynamic generation is complex (needs invertible matrix)
            key_matrix = np.array([[3, 3], [2, 5]])
            ciphertext = hill_encrypt(ciphertext, key_matrix)
            infos.append(("Hill", key_matrix))
            
        elif chosen == "Monoalphabetic":
            # Monoalphabetic key is too complex for KDF derivation, stick to random shuffle
            key_map, rev_map = monoalphabetic_generate_key()
            ciphertext = monoalphabetic_encrypt(ciphertext, key_map)
            infos.append(("Monoalphabetic", (key_map, rev_map)))
            
    # Modern next (AES/DES keys are already randomly generated inside their functions)
    for chosen in modern_sequence:
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




# ==================== Multi-Cipher System (UPGRADED with KDF) ====================

def random_multi_decrypt(ciphertext, infos_json):
    # Deserialize the complex keys/info list first
    infos = deserialize_info(infos_json)
    
    # 🟢 CRITICAL CHANGE 1: Extract the Master Seed
    if infos and infos[0][0] == "MASTER_SEED":
        master_seed = infos[0][1]
        infos = infos[1:] # Remove master seed from the list of ciphers
    else:
        # Fallback (should not happen if encryption worked)
        raise ValueError("Decryption failed: Master Seed not found in session data.")

    # Decrypt in reverse order
    for i, (name, original_key) in reversed(list(enumerate(infos))):
        
        if name in ["Caesar", "Vigenere", "RailFence"]:
            # 🟢 CRITICAL CHANGE 2: Re-derive the classical key using Master Seed (only for Vigenere, Caesar, RailFence)
            
            # The purpose string must exactly match the one used during encryption
            purpose = f"{name}_KEY_{i}"
            
            # Since Hill and Monoalphabetic keys are stored directly, we use the original_key for them.
            # Only Vigenere, Caesar, and RailFence keys were derived in random_multi_encrypt

            if name == "Caesar":
                # KDF key derivation logic must be repeated to get the *same* key
                key_bytes = derive_key(master_seed, purpose, 4)
                shift = int.from_bytes(key_bytes, byteorder='big') % 25 + 1 
                ciphertext = caesar_decrypt(ciphertext, shift)
                
            elif name == "Vigenere":
                key = original_key # The key (string) is stored, so use the original key directly.
                ciphertext = vigenere_decrypt(ciphertext, key)
                
            elif name == "RailFence":
                key_bytes = derive_key(master_seed, purpose, 4)
                rails = int.from.bytes(key_bytes, byteorder='big') % 6 + 2
                ciphertext = rail_fence_decrypt(ciphertext, rails)

        elif name == "Hill":
            ciphertext = hill_decrypt(ciphertext, original_key)
            
        elif name == "Monoalphabetic":
            ciphertext = monoalphabetic_decrypt(ciphertext, original_key[1])
            
        elif name == "AES":
            ciphertext = aes_decrypt(ciphertext, original_key) 
            
        elif name == "DES":
            ciphertext = des_decrypt(ciphertext, original_key)
            
        elif name == "RSA":
            ciphertext = rsa_decrypt(ciphertext, original_key)
            
        else:
             # Fallback
             print(f"Unknown cipher step: {name}")

    return ciphertext
    
# ==================== ATTACK HELPERS (unchanged) ====================

# Improved Common Word List
COMMON_WORDS = {
    "the","and","is","in","to","that","it","of","for","on","with","as","are",
    "this","you","not","we","they","at","be","was","by","have","from","had",
    "will","which","or","but"
}

def english_score(text):
    """A better simple scoring: fraction of common words present."""
    t = text.lower()
    score = 0
    # Use regex to split text into words, removing punctuation
    word_list = re.split(r'[^a-z]+', t)

    for w in COMMON_WORDS:
        if w in word_list:
            score += 1

    # Normalize score
    return score / len(COMMON_WORDS)

# Caesar brute force: try all shifts, pick best by english_score
def attack_caesar(ciphertext):
    best = {"shift": None, "plaintext": None, "score": -1}
    for s in range(26):
        pt = caesar_decrypt(ciphertext, s)
        sc = english_score(pt)
        if sc > best["score"]:
            best = {"shift": s, "plaintext": pt, "score": sc}
    return best

# Rail-Fence brute force try rails 2..8
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

# ==================== VIGENERE KASISKI ATTACK ====================

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def find_key_length(ciphertext):
    """Finds the most probable key length using the Kasiski Examination."""
    text = ''.join(ch.upper() for ch in ciphertext if ch.isalpha())

    # 1. Find repeated sequences of length 3 or more
    distances = []
    for length in range(3, 6):
        for i in range(len(text) - length):
            sequence = text[i:i+length]
            # Find subsequent occurrences
            for j in range(i + length, len(text) - length + 1):
                if text[j:j+length] == sequence:
                    distances.append(j - i)

    # 2. Find the greatest common divisor (GCD) of the distances
    if not distances:
        return 5 # Default guess if no repetitions are found (or text is too short)

    def find_gcd_list(numbers):
        if len(numbers) < 2:
            return numbers[0] if numbers else 1
        result = numbers[0]
        for i in range(1, len(numbers)):
            result = gcd(result, numbers[i])
        return result

    key_guess = find_gcd_list(distances)

    # Filter for reasonable key lengths
    if key_guess > 1 and key_guess <= 15:
        return key_guess

    return 5 # Fallback

def attack_vigenere_for_length(ciphertext, key_length):
    """Performs frequency analysis on sub-ciphertexts to find the key."""
    text = ''.join(ch.upper() for ch in ciphertext if ch.isalpha())

    key = []
    # English letter frequencies
    freq_eng = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
                0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
                0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
                0.00978, 0.02360, 0.00150, 0.01974, 0.00074]

    for i in range(key_length):
        sub_cipher = [text[j] for j in range(i, len(text), key_length)]
        best_shift = 0
        min_chi_sq = float('inf')

        # Try all 26 Caesar shifts on the sub-cipher
        for shift in range(26):
            chi_sq = 0

            decrypted_freq = [0] * 26
            for char in sub_cipher:
                decrypted_char_idx = (ord(char) - ord('A') - shift) % 26
                decrypted_freq[decrypted_char_idx] += 1

            # Calculate Chi-Squared statistic
            total_len = len(sub_cipher)
            if total_len == 0: continue

            for k in range(26):
                expected_count = total_len * freq_eng[k]
                observed_count = decrypted_freq[k]

                # Check to prevent division by zero, although not strictly needed for chi-sq calc
                if expected_count > 0:
                    chi_sq += (observed_count - expected_count)**2 / expected_count

            if chi_sq < min_chi_sq:
                min_chi_sq = chi_sq
                best_shift = shift

        # Convert shift to a letter
        key.append(chr(best_shift + ord('A')))

    return "".join(key)

def attack_vigenere(ciphertext):
    """Main Vigenere attack function."""
    key_length = find_key_length(ciphertext)
    # Only proceed with frequency analysis if text is long enough for reliable analysis
    if len(''.join(ch for ch in ciphertext if ch.isalpha())) < 50:
             return {"key_length": 0, "key": "", "plaintext": "", "score": -1}

    key = attack_vigenere_for_length(ciphertext, key_length)

    # Decrypt and score
    plaintext = vigenere_decrypt(ciphertext, key)
    score = english_score(plaintext)

    return {"key_length": key_length, "key": key, "plaintext": plaintext, "score": score}

# ==================== UTILITY FUNCTIONS ====================


def derive_key(master_seed, purpose_str, length):
    """
    Derives a deterministic key using PBKDF2 from the master_seed and a unique purpose.
    length is the desired output length (in bytes).
    """
    # Purpose string acts as a unique salt/context
    salt = purpose_str.encode('utf-8')
    # Count 100000 is for good measure, making brute force slow
    return PBKDF2(master_seed, salt, dkLen=length, count=100000, hmac_hash_module=SHA512)
    
def is_base64(s):
    try:
        # Check if the length is a multiple of 4, a requirement for standard base64
        if len(s) % 4 != 0:
            return False
        b = base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

def entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    length = len(s)
    for v in freq.values():
        p = v / length
        ent -= p * math.log2(p)
    return ent

def generate_session_id(length=8):
    """Generates a secure, random session ID using secrets module."""
    chars = string.ascii_letters + string.digits
    # CRITICAL CHANGE: Use secrets.choice for cryptographic strength
    return ''.join(secrets.choice(chars) for _ in range(length))
# ==================== Flask Routes ====================

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
        # Print the error for debugging, but return a general error to the user
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
    ent = entropy(c)
    base64_flag = is_base64(c)

    # run attacks
    caesar_attack = attack_caesar(c)
    rail_attack = attack_rail_fence(c)
    vigenere_attack = attack_vigenere(c)

    # collect candidate plaintexts if they look promising
    candidates = []
    success = False
    # threshold for considering an attack "successful" (simple heuristic)
    SCORE_THRESHOLD = 0.30

    if caesar_attack["score"] >= SCORE_THRESHOLD:
        success = True
        candidates.append({
            "type": "Caesar",
            "score": round(caesar_attack["score"], 3),
            "plaintext": caesar_attack["plaintext"],
            "meta": f"shift={caesar_attack['shift']}"
        })

    if rail_attack["score"] >= SCORE_THRESHOLD:
        success = True
        candidates.append({
            "type": "RailFence",
            "score": round(rail_attack["score"], 3),
            "plaintext": rail_attack["plaintext"],
            "meta": f"rails={rail_attack['rails']}"
        })

    # Check Vigenere attack success
    if vigenere_attack["score"] >= SCORE_THRESHOLD and vigenere_attack["key_length"] > 1:
        success = True
        candidates.append({
            "type": "Vigenere",
            "score": round(vigenere_attack["score"], 3),
            "plaintext": vigenere_attack["plaintext"],
            "meta": f"key={vigenere_attack['key']} (len={vigenere_attack['key_length']})"
        })

    # Compute a strength score (0..100)
    ent_norm = min(ent, 8.0) / 8.0 # 0..1
    base_strength = ent_norm * 100

    # if looks like base64 (likely modern cipher), boost strength
    if base64_flag:
        base_strength = max(base_strength, 85)

    # penalty per successful classical attack (each reduces strength)
    penalty = 0
    # Penalty calculation now accounts for Vigenere
    if caesar_attack["score"] >= SCORE_THRESHOLD: penalty += 1
    if rail_attack["score"] >= SCORE_THRESHOLD: penalty += 1
    if vigenere_attack["score"] >= SCORE_THRESHOLD: penalty += 1

    # Scale penalty based on number of successful attacks
    strength_value = int(max(0, min(100, base_strength - penalty * 15))) # Reduced penalty impact

    # map to label
    if strength_value >= 80:
        strength_label = "Strong"
    elif strength_value >= 50:
        strength_label = "Medium"
    else:
        strength_label = "Weak"

    conclusion = ""
    if base64_flag:
        conclusion = ("Ciphertext looks like base64 (likely modern cipher AES/DES/RSA). "
                      "Modern ciphers are not vulnerable to these simple classical attacks.")
    else:
        if ent < 3.5:
            conclusion = "Low ciphertext entropy — classical attacks may have some chance."
        elif ent < 4.5:
            conclusion = "Medium entropy — mixed security; some classical attacks may fail."
        else:
            conclusion = "High entropy — looks random; classical attacks unlikely to succeed."

    return jsonify({
        "status": "ok",
        "entropy": round(ent, 3),
        "is_base64": base64_flag,
        "findings": [
            {
                "type": "Caesar",
                "success": caesar_attack["score"] >= SCORE_THRESHOLD,
                "score": round(caesar_attack["score"], 3)
            },
            {
                "type": "RailFence",
                "success": rail_attack["score"] >= SCORE_THRESHOLD,
                "score": round(rail_attack["score"], 3)
            },
            # Vigenere finding
            {
                "type": "Vigenere",
                "success": vigenere_attack["score"] >= SCORE_THRESHOLD,
                "score": round(vigenere_attack["score"], 3)
            }
        ],
        "candidates": candidates,
        "success": success,
        "strength": strength_value,
        "strength_label": strength_label,
        "conclusion": conclusion
    })

if __name__ == "__main__":
    # This section is ONLY for running locally (i.e., not Gunicorn)
    app.run(debug=True)