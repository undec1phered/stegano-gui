#!/usr/bin/env python3

import cv2
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


HASH_LEN = 32
LEN_DIGITS = 5

def _pixels(img):
    h, w = img.shape[:2]
    for row in range(h):
        for col in range(w):
            for ch in range(3):
                yield row, col, ch


def encode(image_path, out_path, message, password):
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError("Could not read image.")
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    data = pwd_hash + f"{len(message):0{LEN_DIGITS}d}" + message
    gen = _pixels(img)
    for char in data:
        try:
            r, c, ch = next(gen)
        except StopIteration:
            raise ValueError("Message too long for this image.")
        img[r, c, ch] = ord(char)
    cv2.imwrite(out_path, img)


def decode(image_path, password):
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError("Could not read image.")
    gen = _pixels(img)
    header = "".join(
        chr(img[r, c, ch])
        for r, c, ch in (next(gen) for _ in range(HASH_LEN + LEN_DIGITS))
    )
    stored_hash, msg_len = header[:HASH_LEN], int(header[HASH_LEN:])
    if hashlib.md5(password.encode()).hexdigest() != stored_hash:
        raise PermissionError("Wrong passcode — you are not authorised.")
    return "".join(
        chr(img[r, c, ch]) for r, c, ch in (next(gen) for _ in range(msg_len))
    )

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Steganography")
        self.resizable(False, False)
        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True, padx=10, pady=10)
        tabs.add(EncryptTab(tabs), text="  Encrypt  ")
        tabs.add(DecryptTab(tabs), text="  Decrypt  ")


class _LabeledEntry(tk.Frame):
    """A label + entry pair packed vertically."""
    def __init__(self, parent, label, show=None):
        super().__init__(parent)
        tk.Label(self, text=label, anchor="w").pack(fill="x")
        self.var = tk.StringVar()
        tk.Entry(self, textvariable=self.var, show=show, width=55).pack(fill="x")

    @property
    def value(self):
        return self.var.get().strip()


class EncryptTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padx=15, pady=15)
        self._src = _LabeledEntry(self, "Source image:")
        self._src.pack(fill="x", pady=(0, 2))
        tk.Button(self, text="Browse…", command=self._pick_src).pack(anchor="w")

        tk.Label(self, text="Secret message:", anchor="w").pack(fill="x", pady=(10, 0))
        self._msg = tk.Text(self, height=5, width=55, wrap="word")
        self._msg.pack(fill="x")

        self._pwd = _LabeledEntry(self, "Passcode:", show="●")
        self._pwd.pack(fill="x", pady=(10, 0))

        tk.Button(self, text="Encrypt & Save", command=self._run,
                  bg="#2e86de", fg="white", padx=8).pack(pady=(12, 0))

    def _pick_src(self):
        path = filedialog.askopenfilename(
            title="Select image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.tiff"), ("All files", "*.*")]
        )
        if path:
            self._src.var.set(path)

    def _run(self):
        src = self._src.value
        msg = self._msg.get("1.0", "end-1c").strip()
        pwd = self._pwd.value
        if not src:
            messagebox.showwarning("Missing input", "Please select a source image.")
            return
        if not msg:
            messagebox.showwarning("Missing input", "Please enter a secret message.")
            return
        if not pwd:
            messagebox.showwarning("Missing input", "Please enter a passcode.")
            return
        out = filedialog.asksaveasfilename(
            title="Save encrypted image as",
            defaultextension=".png",
            filetypes=[("PNG image", "*.png")]
        )
        if not out:
            return
        try:
            encode(src, out, msg, pwd)
            messagebox.showinfo("Success", f"Encrypted image saved to:\n{out}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


class DecryptTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padx=15, pady=15)
        self._src = _LabeledEntry(self, "Encrypted image:")
        self._src.pack(fill="x", pady=(0, 2))
        tk.Button(self, text="Browse…", command=self._pick_src).pack(anchor="w")

        self._pwd = _LabeledEntry(self, "Passcode:", show="●")
        self._pwd.pack(fill="x", pady=(10, 0))

        tk.Button(self, text="Decrypt", command=self._run,
                  bg="#10ac84", fg="white", padx=8).pack(pady=(12, 0))

        tk.Label(self, text="Decrypted message:", anchor="w").pack(fill="x", pady=(14, 0))
        self._result = tk.Text(self, height=5, width=55, wrap="word", state="disabled",
                               bg="#f0f0f0")
        self._result.pack(fill="x")

    def _pick_src(self):
        path = filedialog.askopenfilename(
            title="Select encrypted image",
            filetypes=[("PNG image", "*.png"), ("All files", "*.*")]
        )
        if path:
            self._src.var.set(path)

    def _run(self):
        src = self._src.value
        pwd = self._pwd.value
        if not src:
            messagebox.showwarning("Missing input", "Please select an encrypted image.")
            return
        if not pwd:
            messagebox.showwarning("Missing input", "Please enter a passcode.")
            return
        try:
            message = decode(src, pwd)
            self._result.config(state="normal")
            self._result.delete("1.0", "end")
            self._result.insert("1.0", message)
            self._result.config(state="disabled")
        except PermissionError as e:
            messagebox.showerror("Unauthorised", str(e))
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    App().mainloop()
