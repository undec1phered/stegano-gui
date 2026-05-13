# stegano-gui

##  Image Steganography

Hide secret messages inside images - right in plain sight.

---

## What even is steganography?

Suppose that Alice wants to send a secret note to Bob, but instead of sending a suspicious-looking encrypted file, Alice sends them a totally normal photo of a cat. Boring, right? Except the message is *hidden inside the pixels*. That's steganography for you, hiding information where no one thinks to look.

This app lets you do exactly that. You pick an image, type a message, set a passcode, and the app quietly tucks your message into the image's pixel data. Nobody can tell by looking at it. Only someone with the right passcode (and this app) can pull the message back out.

---

## Features

- **Encrypt** - hide a message inside any image, locked with a passcode
- **Decrypt** - extract the hidden message from an image using the correct passcode
- **GUI** - clean tabbed interface, no terminal needed
- **Hex encoding + 1-bit LSB** — the message is converted to a hex string; each hex nibble bit is stored in the **lowest bit** of a pixel channel. Maximum pixel change: ±1/255, making visual differences effectively imperceptible.
- **XOR encryption** — messages are encrypted with a password-keyed XOR stream before embedding; the algorithm tag is stored in the image and auto-detected on decryption (including legacy payloads)
- **Randomised header placement** — the password hash, algorithm tag, and message length are stored at pixel positions chosen by a fixed-seed PRNG rather than at predictable sequential positions, making the header harder to locate

---

## Getting started

You'll need Python 3.8+ and one dependency:

```bash
pip install opencv-python
```

Then just run:

```bash
python3 stegano_gui.py
```

---

## How to use it

**To hide a message:**
1. Open the **Encrypt** tab
2. Pick a source image (PNG, JPG, BMP, etc.)
3. Type your secret message
4. Set a passcode
5. Hit **Encrypt & Save** - choose where to save the output (always save as PNG!)

**To read a hidden message:**
1. Open the **Decrypt** tab
2. Select the encrypted PNG
3. Enter the passcode
4. Hit **Decrypt** - your message shows up in the box below it

---

## How it actually works

The app encodes messages through a three-stage pipeline:
1. **Encrypt** — encrypt the raw message bytes with XOR using a key stream derived from the passcode via PBKDF2-HMAC-SHA256 with a dedicated stream salt (distinct from the password-verification hash below).
2. **Hex-encode** — convert the encrypted bytes to a lowercase hex string (e.g. `"hi"` → `"6869"`). Each character is a hex digit in `[0-9a-f]`, which maps to a 4-bit nibble (0–15).
3. **Embed (1-bit LSB)** — each nibble is split into 4 bits, then one bit is written into the **lowest bit** of each pixel channel. The maximum change to any channel value is **±1 out of 255**.
A 76-character header is stored first:
- (upcoming) **PBKDF2-HMAC-SHA256 hash** of your passcode (64 chars, 200 000 iterations) — used to verify the passcode at decode time; the high iteration count makes brute-force attacks expensive --> stay tuned!
- **Algorithm index** (2 chars, zero-padded) — so the decoder knows how to decrypt
- **Payload length** (10 chars, zero-padded) — so the decoder knows how many hex chars to read
The header is written at **randomised pixel positions** chosen by a fixed-seed PRNG, so that it's not saved at the beginning of the image in a sequential block. The hex payload fills the remaining channels in order, skipping the header slots.
On decryption, the same PRNG seed recreates the header positions, the header is read and the passcode is verified, and then the payload is decoded and decrypted automatically.

---

## A couple of things to keep in mind
- **Always save the output as PNG.** JPEG compression will scramble the hidden data and you'll lose the message.
- The image needs to be big enough to hold your message — with 1-bit LSB, each hex character needs 4 channels. As a rule of thumb, usable message length is about `total_channels / 8` text characters (before header overhead), since text bytes are hex-encoded first.

---

