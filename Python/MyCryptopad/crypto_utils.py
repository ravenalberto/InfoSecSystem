# crypto_utils.py
import random
# We removed hashlib because we are using your custom cipher now!

# --- 1. THE SONG LIBRARY ---
SONG_LIBRARY = {
    "Bohemian Rhapsody": "Is this the real life? Is this just fantasy? Caught in a landslide, no escape from reality.",
    "Happy Birthday": "Happy birthday to you, happy birthday to you, happy birthday dear friend, happy birthday to you.",
    "Twinkle Star": "Twinkle, twinkle, little star, how I wonder what you are! Up above the world so high, like a diamond in the sky.",
    "Never Gonna Give You Up": "Never gonna give you up, never gonna let you down, never gonna run around and desert you.",
    "Imagine": "Imagine there's no heaven, it's easy if you try. No hell below us, above us only sky."
}

# --- 2. HELPER: XOR ALGORITHM ---
# This is the heart of your system. Both Passwords and Entries use this now.
def xor_process(data, key):
    result = []
    key_length = len(key)
    
    for i in range(len(data)):
        data_char_code = ord(data[i])
        key_char_code = ord(key[i % key_length]) 
        
        encrypted_code = data_char_code ^ key_char_code
        result.append(chr(encrypted_code))
        
    return "".join(result)

# --- 3. PASSWORD ENCRYPTION (Replaced SHA256 with Song Cipher) ---

def generate_salt():
    """
    Instead of a random number, our 'Salt' is a random Song Title!
    """
    return random.choice(list(SONG_LIBRARY.keys()))

def hash_password(password, song_title):
    """
    Encrypts the password using the lyrics of the chosen song.
    """
    # 1. Get the lyrics (The Key)
    # If the song title doesn't exist (safety check), use a default
    lyrics = SONG_LIBRARY.get(song_title, "Default Key for Safety")
    
    # 2. XOR the password with the Lyrics
    encrypted_password = xor_process(password, lyrics)
    
    # 3. Return as Hex (so it looks like a cool crypto hash in the DB)
    return encrypted_password.encode('utf-8').hex()

def verify_password(stored_hash, song_title, input_password):
    """
    Checks if the input password matches the stored one.
    """
    # We just run the same encryption again and see if it matches the DB
    check_hash = hash_password(input_password, song_title)
    return stored_hash == check_hash

# --- 4. DATA ENCRYPTION (The Song Logic for Diary Entries) ---

def encrypt_data(plaintext, user_password):
    """
    Encrypts the diary entry.
    Key = Song Lyrics + User Password
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
    
    # D. Convert to Hex
    encrypted_hex = encrypted_raw.encode('utf-8').hex()
    
    # E. Return format: SongName|HexData
    return f"{song_title}|{encrypted_hex}"

def decrypt_data(encrypted_blob_string, user_password):
    """
    Decrypts the diary entry.
    """
    try:
        if isinstance(encrypted_blob_string, bytes):
            encrypted_blob_string = encrypted_blob_string.decode('utf-8')

        if "|" not in encrypted_blob_string:
            return "Error: Corrupted Data"
            
        song_title, encrypted_hex = encrypted_blob_string.split("|", 1)
        
        if song_title not in SONG_LIBRARY:
            return "Error: Unknown Song Key"
            
        song_lyrics = SONG_LIBRARY[song_title]
        
        # Reconstruct Master Key
        master_key = song_lyrics + user_password
        
        # Convert Hex back to Raw String
        encrypted_raw = bytes.fromhex(encrypted_hex).decode('utf-8')
        
        # Perform XOR Decryption
        decrypted_text = xor_process(encrypted_raw, master_key)
        
        return decrypted_text
        
    except Exception as e:
        print(f"Decryption error: {e}")
        return None
