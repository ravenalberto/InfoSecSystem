# crypto_utils.py
import hashlib
import random
import base64

# --- 1. THE SONG LIBRARY ---
# The "Cipher Key" comes from these lyrics.
SONG_LIBRARY = {
    "Bohemian Rhapsody": "Is this the real life? Is this just fantasy? Caught in a landslide, no escape from reality.",
    "Happy Birthday": "Happy birthday to you, happy birthday to you, happy birthday dear friend, happy birthday to you.",
    "Twinkle Star": "Twinkle, twinkle, little star, how I wonder what you are! Up above the world so high, like a diamond in the sky.",
    "Never Gonna Give You Up": "Never gonna give you up, never gonna let you down, never gonna run around and desert you.",
    "Imagine": "Imagine there's no heaven, it's easy if you try. No hell below us, above us only sky."
}

# --- 2. HELPER: XOR ALGORITHM ---
# This is a classic "Simple" encryption method.
# It takes the data and "mixes" it with the key. Running it again unmixes it.
def xor_process(data, key):
    result = []
    key_length = len(key)
    
    # Loop through every character in the data
    for i in range(len(data)):
        # Get the character code (ASCII) of the data and the key
        data_char_code = ord(data[i])
        key_char_code = ord(key[i % key_length]) # Wrap around the key if data is longer
        
        # XOR them together (^)
        encrypted_code = data_char_code ^ key_char_code
        
        # Turn back into a character and add to result
        result.append(chr(encrypted_code))
        
    return "".join(result)

# --- 3. PASSWORD HASHING (For Login) ---
# We use standard SHA256 for login security (separate from the note encryption)
def generate_salt():
    return str(random.randint(1000, 9999))

def hash_password(password, salt):
    # Combine password + salt
    combined = password + salt
    # Hash it
    return hashlib.sha256(combined.encode()).hexdigest()

def verify_password(stored_hash, salt, input_password):
    return stored_hash == hash_password(input_password, salt)

# --- 4. DATA ENCRYPTION (The Song Logic) ---
def encrypt_data(plaintext, user_password):
    """
    1. Picks a random song.
    2. Combines Song Lyrics + User Password to make a Master Key.
    3. Encrypts using XOR.
    4. Returns a string: "SongTitle|EncryptedDataInHex"
    """
    if not plaintext:
        return ""

    # A. Pick a random song
    song_title = random.choice(list(SONG_LIBRARY.keys()))
    song_lyrics = SONG_LIBRARY[song_title]
    
    # B. Create the Master Key (Lyrics + Password)
    master_key = song_lyrics + user_password
    
    # C. Perform XOR Encryption
    encrypted_raw = xor_process(plaintext, master_key)
    
    # D. Convert to Hex (so we can save it in the database safely)
    # We take the raw encrypted string and turn it into hex numbers
    encrypted_hex = encrypted_raw.encode('utf-8').hex()
    
    # E. Return format: SongName|HexData
    # We MUST save the song name, otherwise we won't know which lyrics to use to decrypt!
    return f"{song_title}|{encrypted_hex}"

def decrypt_data(encrypted_blob_string, user_password):
    """
    1. Splits the string to find the Song Title.
    2. Reconstructs the Master Key (Lyrics + User Password).
    3. Decrypts using XOR.
    """
    try:
        # We stored it as bytes in the DB, so decode to string first if necessary
        if isinstance(encrypted_blob_string, bytes):
            encrypted_blob_string = encrypted_blob_string.decode('utf-8')

        # A. Split the stored data: "Title|HexData"
        if "|" not in encrypted_blob_string:
            return "Error: Corrupted Data"
            
        song_title, encrypted_hex = encrypted_blob_string.split("|", 1)
        
        # B. Check if song exists
        if song_title not in SONG_LIBRARY:
            return "Error: Unknown Song Key"
            
        song_lyrics = SONG_LIBRARY[song_title]
        
        # C. Reconstruct Master Key
        master_key = song_lyrics + user_password
        
        # D. Convert Hex back to Raw String
        encrypted_raw = bytes.fromhex(encrypted_hex).decode('utf-8')
        
        # E. Perform XOR Decryption (XOR works both ways!)
        decrypted_text = xor_process(encrypted_raw, master_key)
        
        return decrypted_text
        
    except Exception as e:
        print(f"Decryption error: {e}")
        return None # Return None means password was wrong or data corrupted