import sqlite3
import secrets
import string
import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk

DB_NAME = 'passwords.db'

# ---------- DB ----------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS socials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            social TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def generate_password(length=16, charset=None):
    if not charset:
        charset = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(charset) for _ in range(length))

def save_to_db(social, password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO socials (social, password) VALUES (?, ?)', (social, password))
        conn.commit()
        return True, password
    except sqlite3.IntegrityError:
        return False, "Social already exists"
    finally:
        conn.close()

def update_password(social, password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT id FROM socials WHERE social = ?', (social,))
    if c.fetchone() is None:
        conn.close()
        return False, "Social not found"
    c.execute('UPDATE socials SET password = ? WHERE social = ?', (password, social))
    conn.commit()
    conn.close()
    return True, password

def delete_social(social):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('DELETE FROM socials WHERE social = ?', (social,))
    conn.commit()
    conn.close()

def get_all_socials():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT social, password FROM socials')
    rows = c.fetchall()
    conn.close()
    return rows

# ---------- GUI ----------
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.configure(bg="#1e1e1e")
        self.root.geometry("500x550")
        self.root.resizable(False, False)

        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Vertical.TScrollbar",
                        gripcount=0,
                        background="#3c3c3c",
                        darkcolor="#3c3c3c",
                        lightcolor="#3c3c3c",
                        troughcolor="#2d2d2d",
                        bordercolor="#1e1e1e",
                        arrowcolor="white")
        
        style.map("Vertical.TScrollbar",
                  background=[("active", "#3c3c3c"), ("!active", "#3c3c3c")],
                  arrowcolor=[("active", "white"), ("!active", "white")],
                  troughcolor=[("!active", "#2d2d2d"), ("active", "#2d2d2d")])
        
        self.label = tk.Label(root, text="Social:", fg="white", bg="#1e1e1e", font=("Segoe UI", 12))
        self.label.pack(pady=5)

        self.entry = tk.Entry(root, width=40, bg="#2d2d2d", fg="white", insertbackground="white")
        self.entry.pack(pady=5)

        # Password options
        self.options_frame = tk.LabelFrame(root, text="Password Options", bg="#1e1e1e", fg="white")
        self.options_frame.pack(pady=5)

        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_specials = tk.BooleanVar(value=True)

        tk.Checkbutton(self.options_frame, text="Uppercase", variable=self.use_uppercase,
                       bg="#1e1e1e", fg="white", selectcolor="#2d2d2d").grid(row=0, column=0, padx=5, sticky="w")
        tk.Checkbutton(self.options_frame, text="Lowercase", variable=self.use_lowercase,
                       bg="#1e1e1e", fg="white", selectcolor="#2d2d2d").grid(row=0, column=1, padx=5, sticky="w")
        tk.Checkbutton(self.options_frame, text="Numbers", variable=self.use_digits,
                       bg="#1e1e1e", fg="white", selectcolor="#2d2d2d").grid(row=0, column=2, padx=5, sticky="w")
        tk.Checkbutton(self.options_frame, text="Specials", variable=self.use_specials,
                       bg="#1e1e1e", fg="white", selectcolor="#2d2d2d").grid(row=0, column=3, padx=5, sticky="w")

        self.length_label = tk.Label(self.options_frame, text="Length:", bg="#1e1e1e", fg="white")
        self.length_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.length_spinbox = tk.Spinbox(self.options_frame, from_=4, to=64, width=5,
                                         bg="#2d2d2d", fg="white", insertbackground="white")
        self.length_spinbox.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.button_frame = tk.Frame(root, bg="#1e1e1e")
        self.button_frame.pack(pady=10)

        self.add_btn = tk.Button(self.button_frame, text="Add", command=self.add_social, bg="#3c3c3c", fg="white", width=10)
        self.add_btn.grid(row=0, column=0, padx=5)

        self.update_btn = tk.Button(self.button_frame, text="Update", command=self.update_social, bg="#3c3c3c", fg="white", width=10)
        self.update_btn.grid(row=0, column=1, padx=5)

        self.delete_btn = tk.Button(self.button_frame, text="Delete", command=self.delete_entry, bg="#3c3c3c", fg="white", width=10)
        self.delete_btn.grid(row=0, column=2, padx=5)

        self.list_btn = tk.Button(self.button_frame, text="List", command=self.list_socials, bg="#3c3c3c", fg="white", width=10)
        self.list_btn.grid(row=0, column=3, padx=5)

        # Frame to hold Text + Scrollbar
        text_frame = tk.Frame(root, bg="#1e1e1e")
        text_frame.pack(pady=10)

        # Text widget
        self.output = tk.Text(text_frame, height=15, width=58, bg="#2d2d2d", fg="white",
                              insertbackground="white", font=("Consolas", 10), wrap="none")
        self.output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.output.yview, style="Vertical.TScrollbar")
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.output.configure(yscrollcommand=scrollbar.set)

    def get_charset(self):
        charset = ''
        if self.use_uppercase.get():
            charset += string.ascii_uppercase
        if self.use_lowercase.get():
            charset += string.ascii_lowercase
        if self.use_digits.get():
            charset += string.digits
        if self.use_specials.get():
            charset += string.punctuation
        return charset

    def add_social(self):
        social = self.entry.get().strip()
        if not social:
            messagebox.showwarning("Warning", "Social cannot be empty.")
            return

        charset = self.get_charset()
        if not charset:
            messagebox.showwarning("Warning", "Select at least one character type.")
            return

        length = int(self.length_spinbox.get())
        password = generate_password(length, charset)
        success, msg = save_to_db(social, password)
        if success:
            messagebox.showinfo("Success", f"Password generated and saved for {social}.")
        else:
            messagebox.showerror("Error", msg)

    def update_social(self):
        social = self.entry.get().strip()
        if not social:
            messagebox.showwarning("Warning", "Social cannot be empty.")
            return

        charset = self.get_charset()
        if not charset:
            messagebox.showwarning("Warning", "Select at least one character type.")
            return

        length = int(self.length_spinbox.get())
        password = generate_password(length, charset)
        success, msg = update_password(social, password)
        if success:
            messagebox.showinfo("Updated", f"New password generated for {social}.")
        else:
            messagebox.showerror("Error", msg)

    def delete_entry(self):
        social = self.entry.get().strip()
        if not social:
            messagebox.showwarning("Warning", "Social cannot be empty.")
            return
        delete_social(social)
        messagebox.showinfo("Deleted", f"Deleted entry for {social}.")

    def list_socials(self):
        self.output.delete("1.0", tk.END)
        socials = get_all_socials()
        if socials:
            for social, pwd in socials:
                self.output.insert(tk.END, f"{social}: {pwd}\n")
        else:
            self.output.insert(tk.END, "No saved socials.\n")


if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
