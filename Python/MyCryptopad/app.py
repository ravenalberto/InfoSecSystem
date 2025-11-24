# app.py
import customtkinter as ctk
import sqlite3
from tkinter import messagebox
import crypto_utils  # Imports your new custom song file
import datetime

# --- Set the appearance ---
ctk.set_appearance_mode("light")

# ##################################################################
#  LOGIN PAGE FRAME
# ##################################################################
class LoginPage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller 

        # --- Top Header Frame ---
        header_frame = ctk.CTkFrame(self, fg_color="#4A6984", height=50, corner_radius=0)
        header_frame.pack(fill="x", side="top")
        header_label = ctk.CTkLabel(header_frame, text="CRYPTOPAD", font=("Arial", 18, "bold"), text_color="white")
        header_label.pack(pady=12)

        # --- Main Login Frame ---
        login_frame = ctk.CTkFrame(self, fg_color="transparent")
        login_frame.pack(fill="both", expand=True, padx=30, pady=20)

        title_label = ctk.CTkLabel(login_frame, text="Sign In", font=("Arial", 30, "bold"))
        title_label.pack(pady=(20, 30))

        # --- Username ---
        username_label = ctk.CTkLabel(login_frame, text="Username", font=("Arial", 14))
        username_label.pack(anchor="w", padx=10)
        self.username_entry = ctk.CTkEntry(login_frame, placeholder_text="Enter Username", height=40, corner_radius=10, border_color="#D3D3D3", border_width=1)
        self.username_entry.pack(fill="x", padx=10, pady=(5, 20))

        # --- Password ---
        password_label = ctk.CTkLabel(login_frame, text="Password", font=("Arial", 14))
        password_label.pack(anchor="w", padx=10)
        self.password_entry = ctk.CTkEntry(login_frame, placeholder_text="Enter Password", show="*", height=40, corner_radius=10, border_color="#D3D3D3", border_width=1)
        self.password_entry.pack(fill="x", padx=10, pady=5)

        # --- Login Error Label ---
        self.error_label = ctk.CTkLabel(login_frame, text="", text_color="red")
        self.error_label.pack(pady=(10, 0))

        # --- "Confirm" Button ---
        login_button = ctk.CTkButton(login_frame, text="Confirm", command=self.login_event, height=40, corner_radius=10, font=("Arial", 16, "bold"), fg_color="#4A6984", hover_color="#3B546A")
        login_button.pack(fill="x", padx=10, pady=(30, 10))

        # --- "Create an account" Button ---
        register_button = ctk.CTkButton(login_frame, text="Don't have an account? Create an account.", 
                                        command=lambda: controller.show_frame(RegisterPage), 
                                        fg_color="transparent", text_color="#C0392B", hover=False)
        register_button.pack()

    def login_event(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            self.error_label.configure(text="Please fill in all fields.")
            return

        # --- Database Login Logic ---
        try:
            self.controller.db_cursor.execute("SELECT user_id, password_hash, salt FROM User_Registration WHERE username = ?", (username,))
            user_data = self.controller.db_cursor.fetchone()

            if user_data:
                user_id, stored_hash, salt = user_data
                
                if crypto_utils.verify_password(stored_hash, salt, password):
                    # --- SUCCESS! ---
                    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.controller.db_cursor.execute(
                        "INSERT INTO User_Logins (user_id, login_timestamp) VALUES (?, ?)",
                        (user_id, now)
                    )
                    self.controller.db_conn.commit()
                    
                    self.controller.set_current_user(user_id) 
                    self.controller.show_frame(HomePage)      
                    self.error_label.configure(text="")       
                    self.username_entry.delete(0, 'end')      
                    self.password_entry.delete(0, 'end')
                else:
                     self.error_label.configure(text="Invalid username or password.")
            else:
                self.error_label.configure(text="Invalid username or password.")

        except sqlite3.Error as e:
            messagebox.showerror("Login Error", f"An error occurred: {e}")

# ##################################################################
#  REGISTER PAGE FRAME
# ##################################################################
class RegisterPage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        header_frame = ctk.CTkFrame(self, fg_color="#4A6984", height=50, corner_radius=0)
        header_frame.pack(fill="x", side="top")
        header_label = ctk.CTkLabel(header_frame, text="CRYPTOPAD", font=("Arial", 18, "bold"), text_color="white")
        header_label.pack(pady=12)

        reg_frame = ctk.CTkFrame(self, fg_color="transparent")
        reg_frame.pack(fill="both", expand=True, padx=30, pady=20)

        title_label = ctk.CTkLabel(reg_frame, text="Create Account", font=("Arial", 30, "bold"))
        title_label.pack(pady=(20, 30))

        username_label = ctk.CTkLabel(reg_frame, text="Username", font=("Arial", 14))
        username_label.pack(anchor="w", padx=10)
        self.username_entry = ctk.CTkEntry(reg_frame, placeholder_text="Enter a unique username", height=40, corner_radius=10, border_color="#D3D3D3", border_width=1)
        self.username_entry.pack(fill="x", padx=10, pady=(5, 20))

        password_label = ctk.CTkLabel(reg_frame, text="Password", font=("Arial", 14))
        password_label.pack(anchor="w", padx=10)
        self.password_entry = ctk.CTkEntry(reg_frame, placeholder_text="Create a master password", show="*", height=40, corner_radius=10, border_color="#D3D3D3", border_width=1)
        self.password_entry.pack(fill="x", padx=10, pady=5)

        confirm_label = ctk.CTkLabel(reg_frame, text="Confirm Password", font=("Arial", 14))
        confirm_label.pack(anchor="w", padx=10, pady=(20, 0))
        self.confirm_entry = ctk.CTkEntry(reg_frame, placeholder_text="Confirm your password", show="*", height=40, corner_radius=10, border_color="#D3D3D3", border_width=1)
        self.confirm_entry.pack(fill="x", padx=10, pady=5)

        self.error_label = ctk.CTkLabel(reg_frame, text="", text_color="red")
        self.error_label.pack(pady=(10, 0))

        create_button = ctk.CTkButton(reg_frame, text="Create Account", command=self.register_event, height=40, corner_radius=10, font=("Arial", 16, "bold"), fg_color="#4A6984", hover_color="#3B546A")
        create_button.pack(fill="x", padx=10, pady=(30, 10))

        login_button = ctk.CTkButton(reg_frame, text="Already have an account? Sign In", 
                                     command=lambda: controller.show_frame(LoginPage), 
                                     fg_color="transparent", text_color="#C0392B", hover=False)
        login_button.pack()

    def register_event(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()

        if not username or not password or not confirm:
            self.error_label.configure(text="Please fill in all fields.")
            return
        
        if password != confirm:
            self.error_label.configure(text="Passwords do not match.")
            return

        try:
            self.controller.db_cursor.execute("SELECT * FROM User_Registration WHERE username = ?", (username,))
            if self.controller.db_cursor.fetchone():
                self.error_label.configure(text="Username already taken.")
                return

            # Custom Crypto: Create salt and hash
            salt = crypto_utils.generate_salt()
            password_hash = crypto_utils.hash_password(password, salt)

            now = datetime.datetime.now().isoformat()
            
            self.controller.db_cursor.execute(
                "INSERT INTO User_Registration (username, password_hash, salt, date_registered) VALUES (?, ?, ?, ?)",
                (username, password_hash, salt, now)
            )
            self.controller.db_conn.commit()

            messagebox.showinfo("Success", "Account created successfully! Please log in.")
            
            self.error_label.configure(text="")
            self.username_entry.delete(0, 'end')
            self.password_entry.delete(0, 'end')
            self.confirm_entry.delete(0, 'end')
            self.controller.show_frame(LoginPage)

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error occurred: {e}")

# ##################################################################
#  HOME PAGE FRAME
# ##################################################################
class HomePage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        self.current_selected_entry_id = None
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=3)
        self.grid_rowconfigure(0, weight=1)

        # --- Left Frame ---
        left_frame = ctk.CTkFrame(self, width=250, corner_radius=0)
        left_frame.grid(row=0, column=0, sticky="nsew")
        
        left_frame.grid_rowconfigure(1, weight=1) 
        
        list_header = ctk.CTkFrame(left_frame, fg_color="#4A6984", corner_radius=0)
        list_header.grid(row=0, column=0, sticky="ew", ipady=5)
        
        list_label = ctk.CTkLabel(list_header, text="My Entries", font=("Arial", 18, "bold"), text_color="white")
        list_label.pack(pady=10)

        self.entry_listbox = ctk.CTkScrollableFrame(left_frame, corner_radius=0)
        self.entry_listbox.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        new_entry_button = ctk.CTkButton(left_frame, text="+ New Entry", command=self.new_entry, height=40, corner_radius=0)
        new_entry_button.grid(row=2, column=0, sticky="ew", padx=5, pady=5)

        # --- Right Frame ---
        right_frame = ctk.CTkFrame(self, fg_color="transparent")
        right_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        
        right_frame.grid_rowconfigure(2, weight=1) 
        right_frame.grid_columnconfigure(0, weight=1)

        top_bar = ctk.CTkFrame(right_frame, fg_color="transparent")
        top_bar.grid(row=0, column=0, sticky="ew")
        
        self.welcome_label = ctk.CTkLabel(top_bar, text="Welcome!", font=("Arial", 16))
        self.welcome_label.pack(side="left", padx=10)
        
        logout_button = ctk.CTkButton(top_bar, text="Logout", width=100, command=lambda: controller.logout())
        logout_button.pack(side="right", padx=10)

        # --- Editor Widgets ---
        self.title_entry = ctk.CTkEntry(right_frame, placeholder_text="Entry Title", height=40, font=("Arial", 16, "bold"))
        self.title_entry.grid(row=1, column=0, sticky="ew", pady=(10, 5))
        
        self.content_text = ctk.CTkTextbox(right_frame, font=("Arial", 14), wrap="word")
        self.content_text.grid(row=2, column=0, sticky="nsew", pady=5)
        
        # --- Button Bar ---
        button_bar = ctk.CTkFrame(right_frame, fg_color="transparent")
        button_bar.grid(row=3, column=0, sticky="ew", pady=5)
        
        self.save_button = ctk.CTkButton(button_bar, text="Save", command=self.save_entry)
        self.save_button.pack(side="left", padx=5)
        
        self.encrypt_button = ctk.CTkButton(button_bar, text="Encrypt", command=self.encrypt_entry)
        self.encrypt_button.pack(side="left", padx=5)
        
        self.decrypt_button = ctk.CTkButton(button_bar, text="Decrypt", command=self.decrypt_entry)
        self.decrypt_button.pack(side="left", padx=5)
        
        self.delete_button = ctk.CTkButton(button_bar, text="Delete", fg_color="#C0392B", hover_color="#A93226", command=self.delete_entry)
        self.delete_button.pack(side="right", padx=5)
        
        self.clear_fields() 

    # --- Homepage Functions ---

    def clear_fields(self, new_entry=False):
        self.current_selected_entry_id = None
        self.title_entry.delete(0, 'end')
        self.content_text.delete("1.0", 'end')
        
        if new_entry:
            self.title_entry.configure(state="normal")
            self.content_text.configure(state="normal")
            self.save_button.configure(state="normal")
            self.encrypt_button.configure(state="normal")
            self.decrypt_button.configure(state="disabled")
            self.delete_button.configure(state="disabled")
            self.title_entry.insert(0, "New Entry Title")
        else: 
            self.title_entry.configure(state="disabled")
            self.content_text.configure(state="disabled")
            self.save_button.configure(state="disabled")
            self.encrypt_button.configure(state="disabled")
            self.decrypt_button.configure(state="disabled")
            self.delete_button.configure(state="disabled")
            
    def load_user_entries(self):
        user_id = self.controller.get_current_user_id()
        if not user_id: return 
            
        self.controller.db_cursor.execute("SELECT username FROM User_Registration WHERE user_id = ?", (user_id,))
        result = self.controller.db_cursor.fetchone()
        if result:
            username = result[0]
            self.welcome_label.configure(text=f"Welcome, {username}!")

        for child in self.entry_listbox.winfo_children():
            child.destroy()
            
        self.controller.db_cursor.execute("SELECT entry_id, title FROM Entries WHERE user_id = ? ORDER BY date_modified DESC", (user_id,))
        entries = self.controller.db_cursor.fetchall()
        
        for entry in entries:
            entry_id, title = entry
            btn = ctk.CTkButton(
                self.entry_listbox,
                text=title,
                fg_color="transparent",
                text_color=("black", "white"),
                hover_color="#E0E0E0",
                anchor="w",
                command=lambda e_id=entry_id: self.load_entry_data(e_id)
            )
            btn.pack(fill="x", padx=2, pady=2)
            
    def new_entry(self):
        self.clear_fields(new_entry=True)

    def load_entry_data(self, entry_id):
        self.current_selected_entry_id = entry_id
        
        self.controller.db_cursor.execute("SELECT title, content, is_encrypted FROM Entries WHERE entry_id = ?", (entry_id,))
        entry_data = self.controller.db_cursor.fetchone()
        
        if not entry_data:
            self.clear_fields()
            return
            
        title, content, is_encrypted = entry_data
        
        self.title_entry.configure(state="normal")
        self.content_text.configure(state="normal")
        self.save_button.configure(state="normal")
        self.delete_button.configure(state="normal")
        
        self.title_entry.delete(0, 'end')
        self.content_text.delete("1.0", 'end')
        
        self.title_entry.insert(0, title)
        
        if is_encrypted:
            # Show which song was used (stored in content) if possible, or just Encrypted
            self.content_text.insert("1.0", f"LOCKED DATA\n(Encrypted with Song Cipher)")
            self.content_text.configure(state="disabled") 
            self.encrypt_button.configure(state="disabled")
            self.decrypt_button.configure(state="normal")
        else:
            if content:
                # Handle both bytes (from old saves) and string (new saves)
                display_content = content
                if isinstance(content, bytes):
                    display_content = content.decode('utf-8')
                self.content_text.insert("1.0", display_content)
            self.content_text.configure(state="normal")
            self.encrypt_button.configure(state="normal")
            self.decrypt_button.configure(state="disabled")

    def save_entry(self):
        title = self.title_entry.get()
        content = self.content_text.get("1.0", 'end-1c')
        now = datetime.datetime.now().isoformat()
        
        if not title:
            messagebox.showwarning("Error", "Title cannot be empty.")
            return

        if self.current_selected_entry_id:
             self.controller.db_cursor.execute("SELECT is_encrypted FROM Entries WHERE entry_id = ?", (self.current_selected_entry_id,))
             result = self.controller.db_cursor.fetchone()
             if result and result[0] == 1:
                messagebox.showwarning("Encrypted", "Cannot save while entry is encrypted. Please decrypt first.")
                return

        # NOTE: We save as bytes (.encode) to be safe with SQLite BLOBs
        if self.current_selected_entry_id:
            self.controller.db_cursor.execute(
                "UPDATE Entries SET title = ?, content = ?, is_encrypted = 0, date_modified = ? WHERE entry_id = ?",
                (title, content.encode('utf-8'), now, self.current_selected_entry_id)
            )
        else:
            user_id = self.controller.get_current_user_id()
            self.controller.db_cursor.execute(
                "INSERT INTO Entries (user_id, title, content, is_encrypted, date_modified) VALUES (?, ?, ?, 0, ?)",
                (user_id, title, content.encode('utf-8'), now)
            )
            self.current_selected_entry_id = self.controller.db_cursor.lastrowid
            
        self.controller.db_conn.commit()
        self.load_user_entries() 
        messagebox.showinfo("Saved", "Entry saved successfully.")

    def delete_entry(self):
        if not self.current_selected_entry_id: return
        if messagebox.askyesno("Delete Entry", "Are you sure you want to delete this entry?"):
            self.controller.db_cursor.execute("DELETE FROM Entries WHERE entry_id = ?", (self.current_selected_entry_id,))
            self.controller.db_conn.commit()
            self.load_user_entries() 
            self.clear_fields() 
            
    def encrypt_entry(self):
        if not self.current_selected_entry_id:
             messagebox.showwarning("Error", "Please save the note before encrypting.")
             return
             
        # 1. Get the password
        dialog = ctk.CTkInputDialog(text="Enter a password to combine with the Song Key:", title="Encrypt Note")
        password = dialog.get_input()
        
        if not password:
            return
            
        # 2. Get the plaintext
        plaintext = self.content_text.get("1.0", 'end-1c')
        
        # 3. Encrypt the data using our CUSTOM Song Cipher
        try:
            # We don't need to encode plaintext to bytes here, our custom util handles it
            encrypted_string = crypto_utils.encrypt_data(plaintext, password)
            
            # 4. Save to DB
            now = datetime.datetime.now().isoformat()
            # We save the string directly as bytes
            self.controller.db_cursor.execute(
                "UPDATE Entries SET content = ?, is_encrypted = 1, date_modified = ? WHERE entry_id = ?",
                (encrypted_string.encode('utf-8'), now, self.current_selected_entry_id)
            )
            self.controller.db_conn.commit()
            
            self.load_entry_data(self.current_selected_entry_id)
            messagebox.showinfo("Success", f"Entry encrypted! Random song selected.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_entry(self):
        if not self.current_selected_entry_id: return

        # 1. Get the password
        dialog = ctk.CTkInputDialog(text="Enter password to UNLOCK this note:", title="Decrypt Note")
        password = dialog.get_input()
        
        if not password: return 
            
        # 2. Get the encrypted blob from the database
        self.controller.db_cursor.execute("SELECT content FROM Entries WHERE entry_id = ?", (self.current_selected_entry_id,))
        encrypted_blob = self.controller.db_cursor.fetchone()[0]
        
        # 3. Try to decrypt using CUSTOM Song Cipher
        decrypted_text = crypto_utils.decrypt_data(encrypted_blob, password)
        
        if decrypted_text and not decrypted_text.startswith("Error"):
            self.content_text.configure(state="normal")
            self.content_text.delete("1.0", 'end')
            self.content_text.insert("1.0", decrypted_text)
            
            self.encrypt_button.configure(state="normal")
            self.decrypt_button.configure(state="disabled")
            
            # Auto-save the decrypted version
            try:
                now = datetime.datetime.now().isoformat()
                self.controller.db_cursor.execute(
                    "UPDATE Entries SET content = ?, is_encrypted = 0, date_modified = ? WHERE entry_id = ?",
                    (decrypted_text.encode('utf-8'), now, self.current_selected_entry_id)
                )
                self.controller.db_conn.commit()
                messagebox.showinfo("Success", "Entry unlocked!")
                
            except sqlite3.Error as e:
                messagebox.showerror("Save Error", f"Failed to save decrypted text: {e}")
            
        else:
            msg = decrypted_text if decrypted_text else "Decryption failed."
            messagebox.showerror("Error", msg)

# ##################################################################
#  MAIN APP CLASS
# ##################################################################
class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CryptoPad - Song Cipher Edition")
        self.geometry("400x550")
        self.resizable(False, False)
        self.current_user_id = None

        # --- Database Connection ---
        try:
            self.db_conn = sqlite3.connect('CryptoPad.db')
            self.db_cursor = self.db_conn.cursor()
            
            # Ensure tables exist (Basic schema creation for safety)
            self.db_cursor.execute('''CREATE TABLE IF NOT EXISTS User_Registration (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                salt TEXT,
                date_registered TEXT
            )''')
            self.db_cursor.execute('''CREATE TABLE IF NOT EXISTS User_Logins (
                login_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                login_timestamp TEXT
            )''')
            self.db_cursor.execute('''CREATE TABLE IF NOT EXISTS Entries (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT,
                content BLOB,
                is_encrypted INTEGER DEFAULT 0,
                date_modified TEXT
            )''')
            self.db_conn.commit()
            
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to connect: {e}")
            self.destroy()
            return
            
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        for F in (LoginPage, RegisterPage, HomePage):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(LoginPage)

    def show_frame(self, page_class):
        frame = self.frames[page_class]
        if page_class == HomePage:
            self.geometry("800x600") 
            self.resizable(True, True)
            frame.load_user_entries() 
        else:
            self.geometry("400x550") 
            self.resizable(False, False)
        frame.tkraise()

    def set_current_user(self, user_id):
        self.current_user_id = user_id

    def get_current_user_id(self):
        return self.current_user_id

    def logout(self):
        self.set_current_user(None) 
        self.show_frame(LoginPage)

    def on_closing(self):
        if hasattr(self, 'db_conn'):
            self.db_conn.close()
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_closing) 
    app.mainloop()