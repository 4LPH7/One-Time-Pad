import customtkinter as ctk
import tkinter.messagebox
import secrets
import base64

def encrypt(plaintext):
    """Generate OTP ciphertext and key [[1]][[6]]"""
    plaintext_bytes = plaintext.encode('utf-8')
    key = secrets.token_bytes(len(plaintext_bytes))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext_bytes, key))
    return base64.b64encode(ciphertext).decode(), base64.b64encode(key).decode()

def decrypt(ciphertext_b64, key_b64):
    """Decrypt ciphertext using provided key [[6]][[10]]"""
    ciphertext = base64.b64decode(ciphertext_b64)
    key = base64.b64decode(key_b64)
    
    if len(ciphertext) != len(key):
        raise ValueError("Key length must match ciphertext length [[1]]")
    
    decrypted = bytes(c ^ k for c, k in zip(ciphertext, key))
    return decrypted.decode('utf-8')

class OTPApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("system")  # Use system theme [[2]]
        self.title("One-Time Pad Encoder/Decoder")
        self.geometry("800x600")
        
        # Create tabbed interface [[3]]
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(padx=20, pady=20, fill="both", expand=True)
        self.encryption_tab = self.tabview.add("Encryption")
        self.decryption_tab = self.tabview.add("Decryption")
        
        # Encryption Tab
        self._create_encryption_ui()
        # Decryption Tab
        self._create_decryption_ui()
        
    def _create_encryption_ui(self):
        """Build encryption interface [[2]][[4]]"""
        ctk.CTkLabel(self.encryption_tab, text="Plaintext:").pack(padx=10, pady=5, anchor="w")
        self.plaintext = ctk.CTkTextbox(self.encryption_tab, height=100)
        self.plaintext.pack(padx=10, pady=5, fill="x")
        
        encrypt_btn = ctk.CTkButton(
            self.encryption_tab,
            text="Encrypt",
            command=self.encrypt,
            fg_color="#28a745",  # Custom green [[4]]
            hover_color="#218838"
        )
        encrypt_btn.pack(padx=10, pady=10)
        
        ctk.CTkLabel(self.encryption_tab, text="Ciphertext:").pack(padx=10, pady=5, anchor="w")
        self.ciphertext = ctk.CTkTextbox(self.encryption_tab, state="disabled", height=50)
        self.ciphertext.pack(padx=10, pady=5, fill="x")
        
        ctk.CTkLabel(self.encryption_tab, text="Secret Key:").pack(padx=10, pady=5, anchor="w")
        self.key = ctk.CTkTextbox(self.encryption_tab, state="disabled", height=50)
        self.key.pack(padx=10, pady=5, fill="x")
        
        # Copy buttons with modern styling [[3]]
        button_frame = ctk.CTkFrame(self.encryption_tab)
        button_frame.pack(padx=10, pady=5, fill="x")
        ctk.CTkButton(
            button_frame,
            text="Copy Ciphertext",
            command=lambda: self.copy_to_clipboard(self.ciphertext),
            fg_color="#007bff",
            hover_color="#0056b3"
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            button_frame,
            text="Copy Key",
            command=lambda: self.copy_to_clipboard(self.key),
            fg_color="#dc3545",
            hover_color="#c82333"
        ).pack(side="right", padx=5)

    def _create_decryption_ui(self):
        """Build decryption interface [[2]][[4]]"""
        ctk.CTkLabel(self.decryption_tab, text="Ciphertext (Base64):").pack(padx=10, pady=5, anchor="w")
        self.ciphertext_input = ctk.CTkTextbox(self.decryption_tab, height=50)
        self.ciphertext_input.pack(padx=10, pady=5, fill="x")
        
        ctk.CTkLabel(self.decryption_tab, text="Secret Key (Base64):").pack(padx=10, pady=5, anchor="w")
        self.key_input = ctk.CTkTextbox(self.decryption_tab, height=50)
        self.key_input.pack(padx=10, pady=5, fill="x")
        
        decrypt_btn = ctk.CTkButton(
            self.decryption_tab,
            text="Decrypt",
            command=self.decrypt,
            fg_color="#28a745",
            hover_color="#218838"
        )
        decrypt_btn.pack(padx=10, pady=10)
        
        ctk.CTkLabel(self.decryption_tab, text="Decrypted Message:").pack(padx=10, pady=5, anchor="w")
        self.result = ctk.CTkTextbox(self.decryption_tab, state="disabled", height=100)
        self.result.pack(padx=10, pady=5, fill="x")
        
        self.error_label = ctk.CTkLabel(self.decryption_tab, text="", text_color="red")
        self.error_label.pack(padx=10, pady=5)

    def encrypt(self):
        """Handle encryption process [[1]][[6]]"""
        plaintext = self.plaintext.get("1.0", "end-1c").strip()
        if not plaintext:
            self.show_error("Encryption Error", "Plaintext cannot be empty")
            return
        
        try:
            ciphertext, key = encrypt(plaintext)
            self.ciphertext.configure(state="normal")
            self.ciphertext.delete("1.0", "end")
            self.ciphertext.insert("1.0", ciphertext)
            self.ciphertext.configure(state="disabled")
            
            self.key.configure(state="normal")
            self.key.delete("1.0", "end")
            self.key.insert("1.0", key)
            self.key.configure(state="disabled")
            
            # Show security reminder
            tkinter.messagebox.showinfo(
                "Security Reminder",
                "⚠️ Keep the key secure and share separately [[1]][[8]]"
            )
        except Exception as e:
            self.show_error("Encryption Failed", str(e))

    def decrypt(self):
        """Handle decryption process [[6]][[10]]"""
        ciphertext = self.ciphertext_input.get("1.0", "end-1c").strip()
        key = self.key_input.get("1.0", "end-1c").strip()
        
        if not ciphertext or not key:
            self.show_error("Decryption Error", "Both fields are required")
            return
        
        try:
            decrypted = decrypt(ciphertext, key)
            self.result.configure(state="normal")
            self.result.delete("1.0", "end")
            self.result.insert("1.0", decrypted)
            self.result.configure(state="disabled")
            self.error_label.configure(text="")
        except Exception as e:
            self.show_error("Decryption Failed", str(e))

    def show_error(self, title, message):
        """Display error messages with custom styling [[3]]"""
        tkinter.messagebox.showerror(title, message)

    def copy_to_clipboard(self, widget):
        """Copy text to clipboard [[4]]"""
        text = widget.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()  # Ensure the clipboard update takes effect

if __name__ == "__main__":
    app = OTPApp()
    app.mainloop()
