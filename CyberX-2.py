from flask import Flask, render_template, request, jsonify
import random
import string
import base64
import math
import numpy as np
import os
import json # New import for serialization

# PyCryptodome imports
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Database import
from flask_sqlalchemy import SQLAlchemy # New import

app = Flask(__name__)

# ==================== DATABASE CONFIGURATION (NEW) ====================
# Use environment variable for production, fallback for development (SQLite)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 
    'sqlite:///sessions.db' # Default to SQLite for local development
).replace("postgres://", "postgresql://", 1) # Render/Heroku support often requires this replacement
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ==================== KEY/INFO SERIALIZATION UTILITIES (NEW) ====================

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

# ==================== DATABASE MODEL (NEW) ====================
class CipherSession(db.Model):
    id = db.Column(db.String(8), primary_key=True) # The 8-char session ID
    ciphertext = db.Column(db.Text, nullable=False)
    # Store the complex 'infos' structure as a JSON string (TEXT field)
    infos_json = db.Column(db.Text, nullable=False)
    
    def __repr__(self):
        return f"<CipherSession {self.id}>"

# ==================== Classical Ciphers (unchanged) ====================
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

# ==================== Modern Ciphers (unchanged) ====================
def pad(s, block=16):
    pad_len = block - (len(s) % block)
    return s + chr(pad_len) * pad_len

def unpad(s):
    if not s:
        return s
    # Ensure s is a string before checking the last character
    if isinstance(s, bytes):
        s = s.decode('latin-1')
    
    pad_char = s[-1]
    pad_len = ord(pad_char)
    # Basic check to avoid crashing if unpad runs on non-padded data
    if pad_len > len(s):
        return s # Return original if padding looks insane
        
    return s[:-pad_len]

def aes_encrypt(plaintext):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = base64.b64encode(cipher.encrypt(pad(plaintext).encode())).decode()
    return ciphertext, key

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    # Decode base64, decrypt, and then decode the result before unpadding
    decrypted_bytes = cipher.decrypt(base64.b64decode(ciphertext))
    plaintext = unpad(decrypted_bytes.decode('latin-1'))
    return plaintext

def des_encrypt(plaintext):
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = base64.b64encode(cipher.encrypt(pad(plaintext,8).encode())).decode()
    return ciphertext, key

def des_decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(base64.b64decode(ciphertext))
    plaintext = unpad(decrypted_bytes.decode('latin-1'))
    return plaintext

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

# ==================== Multi-Cipher System (MODIFIED DECRYPT) ====================
def random_multi_encrypt(text):
    classical = ["Caesar", "Vigenere", "RailFence", "Hill", "Monoalphabetic"]
    modern = ["AES", "DES", "RSA"]
    num_classical = random.randint(1, 3)
    num_modern = random.randint(1, 2)
    classical_sequence = random.sample(classical, num_classical)
    modern_sequence = random.sample(modern, num_modern)
    infos = []
    ciphertext = text
    # Classical first
    for chosen in classical_sequence:
        if chosen == "Caesar":
            ciphertext = caesar_encrypt(ciphertext, 3)
            infos.append(("Caesar", 3))
        elif chosen == "Vigenere":
            ciphertext = vigenere_encrypt(ciphertext, "KEY")
            infos.append(("Vigenere", "KEY"))
        elif chosen == "RailFence":
            ciphertext = rail_fence_encrypt(ciphertext, 3)
            infos.append(("RailFence", 3))
        elif chosen == "Hill":
            key_matrix = np.array([[3, 3], [2, 5]])
            ciphertext = hill_encrypt(ciphertext, key_matrix)
            infos.append(("Hill", key_matrix))
        elif chosen == "Monoalphabetic":
            key_map, rev_map = monoalphabetic_generate_key()
            ciphertext = monoalphabetic_encrypt(ciphertext, key_map)
            infos.append(("Monoalphabetic", (key_map, rev_map)))
    # Modern next
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
            # We store the private key for decryption
            infos.append(("RSA", priv)) 
    return ciphertext, infos

def random_multi_decrypt(ciphertext, infos_json): # Accepts JSON string
    # Deserialize the complex keys/info list first
    infos = deserialize_info(infos_json) 
    
    for name, key in reversed(infos):
        if name == "Caesar":
            ciphertext = caesar_decrypt(ciphertext, key)
        elif name == "Vigenere":
            ciphertext = vigenere_decrypt(ciphertext, key)
        elif name == "RailFence":
            ciphertext = rail_fence_decrypt(ciphertext, key)
        elif name == "Hill":
            # key is a NumPy array
            ciphertext = hill_decrypt(ciphertext, key)
        elif name == "Monoalphabetic":
            # key is the tuple (map, rev_map), use key[1] for rev_map
            ciphertext = monoalphabetic_decrypt(ciphertext, key[1]) 
        elif name == "AES":
            # key is bytes
            ciphertext = aes_decrypt(ciphertext, key)
        elif name == "DES":
            # key is bytes
            ciphertext = des_decrypt(ciphertext, key)
        elif name == "RSA":
            # key is the RSA private key object
            ciphertext = rsa_decrypt(ciphertext, key)
    return ciphertext

# ==================== Simple attack helpers (unchanged) ====================
COMMON_WORDS = {"the","and","is","in","to","that","it","of","for","on","with","as","are","this","you","not"}

def english_score(text):
    # simple scoring: fraction of common words present
    t = text.lower()
    score = 0
    for w in COMMON_WORDS:
        if w in t:
            score += 1
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

def is_base64(s):
    try:
        # validate base64 by attempting decode and re-encode
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

# Function to generate a random 8-char session ID
def generate_session_id(length=8):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

# ==================== Flask Routes (MODIFIED) ====================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    text = request.form.get("message", "")
    if not text:
        return jsonify({"result": "Error: Message is empty"}), 400

    cipher, infos = random_multi_encrypt(text)
    
    # Generate unique session ID
    session_id = generate_session_id()
    
    # --- DATABASE WRITE ---
    with app.app_context():
        # Ensure session ID is unique (unlikely to collide, but good practice)
        while CipherSession.query.get(session_id): 
            session_id = generate_session_id()

        # Create new database entry
        new_session = CipherSession(
            id=session_id,
            ciphertext=cipher,
            infos_json=serialize_info(infos) # Serialize infos before storing
        )
        db.session.add(new_session)
        db.session.commit()
    # -----------------------
    
    return jsonify({"result": cipher, "session_id": session_id})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    session_id = request.form.get("session_id", "").strip()
    
    if not session_id:
        return jsonify({"result": "Error: Session ID is required for decryption."}), 400

    # --- DATABASE READ ---
    with app.app_context():
        session_data = CipherSession.query.get(session_id)
    # ---------------------
    
    if session_data is None:
        return jsonify({"result": f"Error: Session ID '{session_id}' not found."}), 404

    # Retrieve ciphertext and serialized encryption info
    ciphertext = session_data.ciphertext
    infos_json = session_data.infos_json # Retrieve JSON string
    
    try:
        # Decrypt using the JSON string (which is deserialized inside the function)
        plain = random_multi_decrypt(ciphertext, infos_json) 
    except Exception as e:
        # Handle decryption errors gracefully (e.g., corrupted key)
        return jsonify({"result": f"Error during decryption: {e}"}), 500

    # Optional: Delete session after successful decryption for cleanup
    # with app.app_context():
    #     db.session.delete(session_data)
    #     db.session.commit()

    return jsonify({"result": plain})

@app.route("/simulate", methods=["POST"])
def simulate():
    session_id = request.form.get("session_id", "").strip()
    
    if not session_id:
        return jsonify({"status": "error", "message": "Session ID is required for simulation."}), 400

    # --- DATABASE READ ---
    with app.app_context():
        session_data = CipherSession.query.get(session_id)
    # ---------------------
    
    if session_data is None:
        return jsonify({"status": "error", "message": f"Session ID '{session_id}' not found."}), 404

    c = session_data.ciphertext # Get ciphertext from the database
    ent = entropy(c)
    base64_flag = is_base64(c)

    # run attacks
    caesar_attack = attack_caesar(c)
    rail_attack = attack_rail_fence(c)

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

    # Compute a strength score (0..100)
    ent_norm = min(ent, 8.0) / 8.0  # 0..1
    base_strength = ent_norm * 100

    # if looks like base64 (likely modern cipher), boost strength
    if base64_flag:
        base_strength = max(base_strength, 85)

    # penalty per successful classical attack (each reduces strength)
    penalty = 0
    for cand in candidates:
        penalty += 0.35  

    strength_value = int(max(0, min(100, base_strength - penalty * 100)))

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
            }
        ],
        "candidates": candidates,
        "success": success,
        "strength": strength_value,
        "strength_label": strength_label,
        "conclusion": conclusion
    })

if __name__ == "__main__":
    # --- Local DB Initialization ---
    # This ensures the SQLite file and tables are created when running locally.
    with app.app_context():
        db.create_all()
    # -------------------------------
    app.run(debug=True)