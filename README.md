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

The app replaces individual pixel channel values (R, G, B) with the ASCII codes of the message characters. The first few pixels store a password hash and the message length as a header, so the app knows where the message starts and ends and can verify your passcode before showing anything.

The visual difference is effectively invisible to the human eye.

---

## A couple of things to keep in mind

- **Always save the output as PNG.** JPEG compression will scramble the hidden data and you'll lose the message.
- The image needs to be big enough to hold your message — roughly `3 × total pixels` characters max.
- The password check uses MD5, which is fine for a casual use but not for anything serious.

---

<!--## License

MIT 

