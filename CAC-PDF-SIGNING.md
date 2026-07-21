# CAC PDF Signer (Linux) — Install & Use

A GUI tool to sign a PDF's **existing signature block(s)** with your CAC on Zorin/Ubuntu.
Built on [pyHanko] (PKCS#11) because it's the one tool that signs *into* a pre-placed
signature field — so the signature shows in the block in Acrobat, and multiple people can
sign their own blocks. (JSignPdf and LibreOffice/OnlyOffice can't do this — see the README.)

**Prerequisite:** `cac-setup.py` has been run (OpenSC + pcscd + DoD certs in `~/.pki/nssdb`).

---

## Install (one command)

`cac-setup.py` sets up the signer for you — the venv (pyHanko + pypdf), the signer script in
`~/bin`, and the launcher — all as your normal user (no sudo):

```bash
python3 cac-setup.py pdf-signer            # install   (undo: pdf-signer --revert)
```

Or fold it into a fresh CAC setup in one shot:

```bash
sudo python3 cac-setup.py --add-pdf-signer     # install certs AND the signer
```

**"Sign PDF with CAC"** then appears in your applications menu and in a PDF's right-click
**Open With**. (The signer program itself is embedded in `cac-setup.py` and written to
`~/bin/cac-sign-pdf-gui.py` on install.)

---

## Sign a PDF

1. **Fill in the form first** (e.g. in OnlyOffice) — the safe habit. Whether you *can* edit
   after signing depends on the signature type (see
   [Does signing lock the document?](#does-signing-lock-the-document)); filling first always
   works.
2. Insert your **CAC**.
3. Right-click the PDF → **Open With → Sign PDF with CAC** (or launch it from the app menu and
   pick the file).
4. If the form has **multiple blocks**, choose yours from the list — blocks are numbered in
   **document order** (top of page down), so #1 is the first block on the page regardless of its
   internal field name.
5. Enter your **CAC PIN**.
6. It writes `<name>_signed.pdf` next to the original and tells you which block it signed (and
   which remain unsigned).

---

## Multiple signers (one document, several blocks)

Signatures are **sequential on one file** — route it signer to signer:

1. Complete **all** form data before anyone signs.
2. **Person A** signs their block → gets `..._signed.pdf` → sends it to **Person B**.
3. **Person B** opens the *signed* file with the tool; only the still-empty blocks are offered.
   They pick theirs and sign.
4. Repeat. Every earlier signature stays valid (verified).

> Note: this covers "fill the whole form, then everyone signs their block." If a signer must
> *type* into their section *and* sign after others have already signed, the form has to be
> authored with per-field locking (DocMDP) — a bigger lift; ask before relying on it.

---

## Does signing lock the document?

Not necessarily — which is why you may be able to fill fields even *after* signing. It depends
on the signature type:

- **Approval signature — what this tool creates.** It does **not** lock the document. Other
  blank fields stay fillable afterward, and the signature remains valid *as long as the edit is
  saved as an incremental update* (Acrobat shows "valid, with changes permitted since
  signing"). This is how DoD forms let each signer complete and sign their own section.
- **Certification (DocMDP) signature.** An author signature — only one, applied first — that
  sets a permission level: **P1** = no changes allowed, **P2** = form-fill + signing allowed,
  **P3** = + annotations. A P1-certified form breaks on any later edit.
- **Field locks (`/Lock`).** A signature field can be built to lock specific fields when
  signed. Editing a *locked* field breaks the signature; an *unlocked* one doesn't.

Two cautions:

- **"Able to type" ≠ "still valid."** After editing, re-check the signature in Acrobat or with
  `pdfsig`. If your editor did a *full re-save* instead of an incremental update, the signature
  can be **destroyed** entirely.
- **Fill-first is still the safe default** — it works regardless of how the form was built, and
  avoids strict validators flagging post-signing changes.

## Verify a signature

- Open the signed PDF in Acrobat (or any viewer) — the signature appears in the block.
- Or on the command line:
  ```bash
  pdfsig file_signed.pdf -nssdir sql:$HOME/.pki/nssdb
  ```
  Expect **"Signature is Valid"** and **"Certificate is Trusted."**

[pyHanko]: https://github.com/MatthiasValvekens/pyHanko
