# ChromTriage

```text
   ________                              _______      _
  / ____/ /_  _________  ____ ___  ___  /_  __(_)____(_)___ _____ ____
 / /   / __ \/ ___/ __ \/ __ `__ \/ _ \  / / / / ___/ / __ `/ __ `/ _ \
/ /___/ / / / /  / /_/ / / / / / /  __/ / / / / /  / / /_/ / /_/ /  __/
\____/_/ /_/_/   \____/_/ /_/ /_/\___/ /_/ /_/_/  /_/\__,_/\__, /\___/
                                                          /____/
```

ChromTriage is a small Python tool for Chrome credential triage.

It is useful if you already have a Chrome loot directory and want to answer two immediate questions fast:

- Does `Local State` contain Chrome key material?
- What is inside `Login Data`, and can I decrypt a specific `v10` blob?

The tool is intentionally narrow. It focuses only on scanning Chrome credential artifacts and decrypting `v10` values when the AES key is already known.

## Requirements

- Python 3
- `pycryptodome`

```bash
pip install pycryptodome
```

## Usage

### Scan

```bash
python3 chromtriage.py scan <path>
```

Examples:

```bash
python3 chromtriage.py scan AppData
python3 chromtriage.py scan /home/kali/Downloads/chromectfs/decrypt
python3 chromtriage.py scan /home/kali/Downloads/chromectfs/decrypt/AppData
```

What `scan` shows:

- The scan path
- The resolved `Local State` path
- Whether `os_crypt.encrypted_key` is present
- The resolved `Login Data` path
- The rows from `logins`

[ screenshot here 🙏 ]

### Decrypt

```bash
python3 chromtriage.py --key <KEY_HEX> --enc <BLOB_HEX>
```

What `decrypt` does:

- Validates the `v10` blob structure
- Uses the supplied AES key to decrypt the blob
- Prints the plaintext result

[ screenshot here 🙏 ]

## Technical Notes

### Scan Logic

The scanner looks for Chrome artifacts in the expected locations for:

- `Local State`
- `Default/Login Data`

It supports both of these layouts:

- Passing the `AppData` directory directly
- Passing a parent directory that contains `AppData`

`Local State` is parsed as JSON to check for `os_crypt.encrypted_key`.

`Login Data` is opened as SQLite in read-only mode and queried with:

```sql
SELECT password_value, origin_url, username_value FROM logins
```

Binary SQLite values are printed as uppercase hex so encrypted Chrome blobs stay readable.


### `v10` Decryption Logic

The decrypt path expects a Chrome `v10` blob and an AES key in hexadecimal.

Technically, the workflow is:

1. Convert both inputs from hex into bytes.
2. Confirm that the blob starts with the `v10` prefix.
3. Split the blob into nonce, ciphertext, and authentication tag.
4. Decrypt and verify it with AES-GCM.
5. Return the plaintext as UTF-8.

## Scope

ChromTriage is not a full browser forensics suite.

It does not recover DPAPI master keys or automate the entire Chrome key recovery chain. Its job is much smaller: quickly inspect Chrome credential artifacts and decrypt `v10` values once the AES key is available. Nothing more.

## License

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted, provided
that the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation, and that the name of M.I.T. not be used in advertising
or publicity pertaining to distribution of the software without specific,
written prior permission.  M.I.T. makes no representations about the
suitability of this software for any purpose.  It is provided "as is"
without express or implied warranty.

M.I.T. DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL M.I.T.
BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.