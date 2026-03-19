import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

V10_PREFIX = b"v10"
NONCE_LENGTH = 12
TAG_LENGTH = 16
AES256_KEY_LENGTH = 32
MIN_V10_BLOB_LENGTH = len(V10_PREFIX) + NONCE_LENGTH + TAG_LENGTH
LOGIN_DATA_PATH = Path("AppData/Local/Google/Chrome/User Data/Default/Login Data")
LOCAL_STATE_PATH = Path("AppData/Local/Google/Chrome/User Data/Local State")
LOGIN_TABLE = "logins"
LOGIN_COLUMNS = ["password_value", "origin_url", "username_value"]


class ChromeDecryptError(ValueError):
    pass


def print_banner():
    print(r"   ________                       ______     _                ")
    print(r"  / ____/ /_  _________  ____ ___/_  __/____(_)___ _____ ____ ")
    print(" / /   / __ \\/ ___/ __ \\/ __ `__ \\/ / / ___/ / __ `/ __ `/ _ \\")
    print(r"/ /___/ / / / /  / /_/ / / / / / / / / /  / / /_/ / /_/ /  __/")
    print(r"\____/_/ /_/_/   \____/_/ /_/ /_/_/ /_/  /_/\__,_/\__, /\___/ ")
    print(r"                                                 /____/       ")
    print("")


def require_crypto():
    if AES is None:
        raise RuntimeError(
            "PyCryptodome is not installed. Install it with 'pip install pycryptodome'."
        )


def hex_to_bytes(value, field_name):
    if not value:
        raise ChromeDecryptError(field_name + " cannot be empty.")
    try:
        return bytes.fromhex(value)
    except ValueError:
        raise ChromeDecryptError(field_name + " is not valid hexadecimal.")


def parse_v10_blob(data):
    if len(data) < MIN_V10_BLOB_LENGTH:
        raise ChromeDecryptError(
            "The blob is too short for v10: " + str(len(data)) + " bytes."
        )
    if not data.startswith(V10_PREFIX):
        raise ChromeDecryptError("The blob does not start with the v10 prefix.")
    nonce_end = len(V10_PREFIX) + NONCE_LENGTH
    tag_start = len(data) - TAG_LENGTH
    return data[len(V10_PREFIX):nonce_end], data[nonce_end:tag_start], data[tag_start:]


def decrypt_chrome_bytes(enc_hex, key_hex):
    require_crypto()
    encrypted_data = hex_to_bytes(enc_hex, "enc_hex")
    key = hex_to_bytes(key_hex, "key_hex")
    if len(key) != AES256_KEY_LENGTH:
        raise ChromeDecryptError(
            "The AES key must be "
            + str(AES256_KEY_LENGTH)
            + " bytes, but it is "
            + str(len(key))
            + "."
        )
    nonce, ciphertext, tag = parse_v10_blob(encrypted_data)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ChromeDecryptError(
            "GCM authentication failed. The key or blob is invalid."
        )


def decrypt_chrome_value(enc_hex, key_hex):
    plaintext = decrypt_chrome_bytes(enc_hex, key_hex)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        raise ChromeDecryptError("The decrypted plaintext is not valid UTF-8.")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Simple Chrome Login Data scan and v10 blob decryption."
    )
    parser.add_argument("--key", help="Chrome AES key in hexadecimal.")
    parser.add_argument("--enc", help="Chrome v10 blob in hexadecimal.")
    subparsers = parser.add_subparsers(dest="mode")
    scan_parser = subparsers.add_parser("scan", help="Scan a Chrome loot directory.")
    scan_parser.add_argument("path", help="Base path to scan.")
    return parser


def format_sqlite_value(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex().upper()
    return str(value)


def open_sqlite_read_only(path):
    sqlite_uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
    return sqlite3.connect(sqlite_uri, uri=True)


def resolve_scan_path(base_path, relative_path):
    base_path = os.path.abspath(os.path.expanduser(base_path))
    direct_path = os.path.abspath(os.path.join(base_path, str(relative_path)))
    appdata_path = os.path.abspath(os.path.join(base_path, "AppData", str(relative_path)))
    if os.path.exists(direct_path):
        return direct_path
    if os.path.exists(appdata_path):
        return appdata_path
    return direct_path


def read_local_state(local_state_path):
    result = {"path": local_state_path, "exists": False, "encrypted_key_present": False}
    if not os.path.exists(local_state_path):
        return result
    result["exists"] = True
    try:
        with open(local_state_path, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ChromeDecryptError("Could not read Local State: " + str(exc))
    result["encrypted_key_present"] = bool(data.get("os_crypt", {}).get("encrypted_key"))
    return result


def read_login_data(login_data_path):
    result = {
        "path": login_data_path,
        "exists": os.path.exists(login_data_path),
        "rows": [],
    }
    if not result["exists"]:
        return result
    try:
        connection = open_sqlite_read_only(login_data_path)
        cursor = connection.cursor()
        result["rows"] = cursor.execute(
            "SELECT " + ", ".join(LOGIN_COLUMNS) + " FROM " + LOGIN_TABLE
        ).fetchall()
    except sqlite3.Error as exc:
        raise ChromeDecryptError("SQLite error: " + str(exc))
    finally:
        if "connection" in locals():
            connection.close()
    return result


def scan_path(base_path):
    base_path = os.path.abspath(os.path.expanduser(base_path))
    if not os.path.exists(base_path):
        raise ChromeDecryptError("The path does not exist: " + base_path)
    local_state_path = resolve_scan_path(base_path, LOCAL_STATE_PATH)
    login_data_path = resolve_scan_path(base_path, LOGIN_DATA_PATH)
    return {
        "scan_path": base_path,
        "local_state": read_local_state(local_state_path),
        "login_data": read_login_data(login_data_path),
    }


def print_scan_summary(result):
    local_state = result["local_state"]
    login_data = result["login_data"]

    print_banner()
    print("Scan Path: " + result["scan_path"])
    print("Local State Path: " + local_state["path"])
    print(
        "encrypted_key Present: "
        + ("yes" if local_state["encrypted_key_present"] else "no")
    )
    print("Login Data Path: " + login_data["path"])
    if not login_data["exists"]:
        return
    print("")
    for row in login_data["rows"]:
        print(" | ".join(format_sqlite_value(value) for value in row))


def run_scan(path):
    print_scan_summary(scan_path(path))


def run_decrypt(args):
    if not args.key or not args.enc:
        raise ChromeDecryptError("You must provide both arguments: --key and --enc.")
    print_banner()
    print(decrypt_chrome_value(args.enc, args.key))


def main():
    parser = build_parser()
    try:
        args = parser.parse_args()
        if args.mode == "scan":
            run_scan(args.path)
        elif args.key or args.enc:
            run_decrypt(args)
        else:
            parser.print_help()
            return 1
    except (ChromeDecryptError, RuntimeError) as exc:
        print("[!] " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
