#!/usr/bin/env python3

import cv2
import hashlib
import hmac
import random
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

_SEED     = 0xDEADBEEF

_PWD_SALT  = b"steganography_app_v2"
_PWD_ITERS = 200_000

_HASH_LEN = 64   # PBKDF2-HMAC-SHA256 → 32 bytes → 64 hex chars
_ALGO_DIG = 2    # zero-padded algorithm index field width
_LEN_DIG  = 10   # zero-padded hex-payload length field width
_HDR_LEN  = _HASH_LEN + _ALGO_DIG + _LEN_DIG   # 76 chars total

ALGOS = ["None", "XOR"]



def _flat_to_pos(flat_idx: int, w: int):
    """Map a flat channel index → (row, col, channel) for a BGR image of width w."""
    ch  = flat_idx % 3
    pix = flat_idx // 3
    return pix // w, pix % w, ch


def _header_flat(total: int):
    """
    Return _HDR_LEN unique flat channel indices chosen by a fixed-seed PRNG.
    These are the positions where the header (hash + algo + length) is stored,
    scattered randomly across the image rather than placed at the start.
    """
    return random.Random(_SEED).sample(range(total), _HDR_LEN)


def _msg_positions(total: int, hdr_set: set):
    """Yield flat channel indices in sequential order, skipping header slots."""
    for i in range(total):
        if i not in hdr_set:
            yield i



def _pwd_hash(password: str) -> str:
    """Return a 64-char hex string derived from password via PBKDF2-HMAC-SHA256."""
    raw = hashlib.pbkdf2_hmac("sha256", password.encode(), _PWD_SALT, _PWD_ITERS)
    return raw.hex()


def _derive_key(secret: str, length: int) -> bytes:
    """ Derive length key bytes from secret using PBKDF2-HMAC-SHA256 (1 iteration).
    This is a key-derivation function for stream-cipher use, not for password storage.
    A dedicated salt and the `dklen` parameter replace the manual iteration loop. """

    return hashlib.pbkdf2_hmac("sha256", secret.encode(), b"steg_xor_keystream_v2", 1, dklen=length)

def _xor(data: bytes, secret: str) -> bytes:
    """XOR every byte of data with a key derived from secret."""
    key = _derive_key(secret, len(data))
    return bytes(b ^ k for b, k in zip(data, key))


def encode(image_path: str, out_path: str, message: str,
           password: str, algo: str = "None") -> None:
    """
    Encrypt message, hex-encode it, and embed it into the carrier image.

    Pipeline:
      message  →  encrypt (optional)  →  hex string  →  4-bit nibbles → lower 4 bits of pixel channels
    Each hex character ('0'-'9', 'a'-'f') maps to a 4-bit nibble (0-15).
    Only the lower 4 bits of each pixel channel are overwritten; the upper 4
    bits are preserved.  Maximum change to any channel value: ±15 out of 255.

    Header layout (76 chars, stored at PRNG-randomised positions):
      [0:64]  PBKDF2-HMAC-SHA256 hash of password (hex)
      [64:66] zero-padded algorithm index
      [66:76] zero-padded length of the hex payload
    """
    if algo not in ALGOS:
        raise ValueError(f"Unknown algorithm {algo!r}. Choose from: {ALGOS}")
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError("Could not read image.")
    h, w = img.shape[:2]
    total = h * w * 3

    raw = message.encode("utf-8")
    if algo == "XOR":
        raw = _xor(raw, password)
    hex_msg = raw.hex()

    hash_field = _pwd_hash(password)
    algo_field = f"{ALGOS.index(algo):0{_ALGO_DIG}d}"
    len_field  = f"{len(hex_msg):0{_LEN_DIG}d}"
    header_str = hash_field + algo_field + len_field

    if _HDR_LEN + len(hex_msg) > total:
        raise ValueError("Message too long for this image.")

    hdr_flat = _header_flat(total)
    for flat_idx, char in zip(hdr_flat, header_str):
        pos = _flat_to_pos(flat_idx, w)
        img[pos] = (int(img[pos]) & 0xF0) | int(char, 16)

    hdr_set = set(hdr_flat)
    msg_gen = _msg_positions(total, hdr_set)
    for char in hex_msg:
        pos = _flat_to_pos(next(msg_gen),w)
        img[pos] = (int(img[pos]) & 0xF0) | int(char, 16)
    cv2.imwrite(out_path, img)


def decode(image_path: str, password: str) -> str:
    """
    Extract and decrypt the hidden message from a steg image.
    Raises PermissionError if the passcode is wrong.
    The encryption algorithm is read from the header - no need to specify it.
    """
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError(":( Could not read image.")
    h, w = img.shape[:2]
    total = h * w * 3

    hdr_flat   = _header_flat(total)
    header_str = "".join(format(int(img[_flat_to_pos(i, w)]) & 0x0F, 'x') for i in hdr_flat)

    stored_hash = header_str[:_HASH_LEN]

    try:
        algo_idx = int(header_str[_HASH_LEN : _HASH_LEN + _ALGO_DIG])
        hex_len  = int(header_str[_HASH_LEN + _ALGO_DIG :])
    except ValueError:
        raise ValueError("Image does not appear to contain a valid steg payload.")

    if not hmac.compare_digest(_pwd_hash(password), stored_hash):
        raise PermissionError(":/ Sorry, wrong passcode.")

    if algo_idx < 0 or algo_idx >= len(ALGOS):
        raise ValueError(f"Unrecognised algorithm index {algo_idx} in header.")

    algo = ALGOS[algo_idx]

    hdr_set = set(hdr_flat)
    msg_gen = _msg_positions(total, hdr_set)
    hex_msg = "".join(
        format(int(img[_flat_to_pos(next(msg_gen), w)]) & 0x0F, 'x') for _ in range(hex_len)
    )

    try:
        raw = bytes.fromhex(hex_msg)
    except ValueError:
        raise ValueError("Payload data is corrupted or the image was re-compressed.")
    if algo == "XOR":
        raw = _xor(raw, password)
    return raw.decode("utf-8")




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

        algo_frame = tk.Frame(self)
        algo_frame.pack(fill="x", pady=(8, 0))
        tk.Label(algo_frame, text="Encryption algorithm:").pack(side="left")
        self._algo = ttk.Combobox(algo_frame, values=ALGOS, state="readonly", width=10)
        self._algo.current(0)
        self._algo.pack(side="left", padx=(8, 0))

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
        src  = self._src.value
        msg  = self._msg.get("1.0", "end-1c").strip()
        pwd  = self._pwd.value
        algo = self._algo.get()
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
            encode(src, out, msg, pwd, algo)
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
