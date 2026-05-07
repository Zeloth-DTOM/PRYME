import json, os, base64, time, requests, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

CONFIG_FILE = "config.json"
DEFAULT_PORT = 5001
DEFAULT_LOCAL_NODE = f"http://127.0.0.1:{DEFAULT_PORT}"

KEY_FILE = "wallet_keys.json"
READ_MESSAGES_FILE = "read_messages.json"

MAX_MESSAGE_LENGTH = 200
INBOX_LIMIT = 50


def load_json(file, default):
    if not os.path.exists(file):
        return default
    try:
        with open(file, "r") as f:
            return json.load(f)
    except:
        return default


def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=2)


def normalize_url(url):
    if not url:
        return None

    url = str(url).strip().rstrip("/")

    if not url:
        return None

    if url == "auto":
        return None

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    return url


def load_config():
    default = {
        "host": "0.0.0.0",
        "port": DEFAULT_PORT,
        "public_url": "auto",
        "seed_url": "",
        "seeds": [],
        "node_url": "auto"
    }

    cfg = load_json(CONFIG_FILE, default)
    changed = False

    for key, value in default.items():
        if key not in cfg:
            cfg[key] = value
            changed = True

    try:
        cfg["port"] = int(cfg.get("port", DEFAULT_PORT))
    except:
        cfg["port"] = DEFAULT_PORT
        changed = True

    if changed or not os.path.exists(CONFIG_FILE):
        save_json(CONFIG_FILE, cfg)

    return cfg


def build_node_list():
    """
    Conservative node selection:
    1. local node from config port: http://127.0.0.1:PORT
    2. node_url, if manually set in config
    3. seed_url from config
    4. public_url, only if it is not auto/localhost
    5. extra seeds list

    This keeps old local behavior but allows packaged clients to use seed_url.
    """
    cfg = load_config()
    nodes = []

    def add(url):
        url = normalize_url(url)
        if url and url not in nodes:
            nodes.append(url)

    port = int(cfg.get("port", DEFAULT_PORT))
    add(f"http://127.0.0.1:{port}")

    add(cfg.get("node_url"))
    add(cfg.get("seed_url"))

    public_url = normalize_url(cfg.get("public_url"))
    if public_url and "127.0.0.1" not in public_url and "localhost" not in public_url:
        add(public_url)

    for seed in cfg.get("seeds", []):
        add(seed)

    if not nodes:
        add(DEFAULT_LOCAL_NODE)

    return nodes


NODES = build_node_list()


def get(path):
    for node in NODES:
        try:
            r = requests.get(node + path, timeout=5)
            return r.json()
        except:
            pass
    print("Node unavailable.")
    print("Tried nodes:", ", ".join(NODES))
    return None


def post(path, data):
    for node in NODES:
        try:
            return requests.post(node + path, json=data, timeout=10)
        except:
            pass
    print("Node unavailable.")
    print("Tried nodes:", ", ".join(NODES))
    return None


def create_wallet():
    """
    Creates two key pairs:
    1. Ed25519 key pair for transaction signatures.
    2. X25519 key pair for encrypted blockchain messages.
    """
    if os.path.exists(KEY_FILE):
        print("Wallet already exists.")
        return

    signing_private = Ed25519PrivateKey.generate()
    signing_public = signing_private.public_key()

    encryption_private = X25519PrivateKey.generate()
    encryption_public = encryption_private.public_key()

    save_json(KEY_FILE, {
        "private_key": base64.b64encode(
            signing_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
        ).decode(),
        "public_key": base64.b64encode(
            signing_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        ).decode(),
        "encryption_private_key": base64.b64encode(
            encryption_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
        ).decode(),
        "encryption_public_key": base64.b64encode(
            encryption_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        ).decode()
    })

    print("Wallet created.")


def load_keys():
    """
    Loads wallet keys from wallet_keys.json.
    Older wallets may not have encryption keys yet.
    """
    keys = load_json(KEY_FILE, None)

    if not keys:
        print("Create wallet first.")
        return None, None, None, None

    signing_private = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(keys["private_key"])
    )

    encryption_private = None
    encryption_public = None

    if "encryption_private_key" in keys and "encryption_public_key" in keys:
        encryption_private = X25519PrivateKey.from_private_bytes(
            base64.b64decode(keys["encryption_private_key"])
        )
        encryption_public = keys["encryption_public_key"]

    return signing_private, keys["public_key"], encryption_private, encryption_public


def ensure_encryption_keys():
    """
    Adds encryption keys to old wallets without changing the existing wallet address.
    """
    keys = load_json(KEY_FILE, None)

    if not keys:
        print("Create wallet first.")
        return False

    if "encryption_private_key" in keys and "encryption_public_key" in keys:
        print("Encryption keys already exist.")
        return True

    encryption_private = X25519PrivateKey.generate()
    encryption_public = encryption_private.public_key()

    keys["encryption_private_key"] = base64.b64encode(
        encryption_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    ).decode()

    keys["encryption_public_key"] = base64.b64encode(
        encryption_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    ).decode()

    save_json(KEY_FILE, keys)

    print("Encryption keys added to existing wallet.")
    return True


def show_address():
    """
    Shows both public keys.
    """
    _, pub, _, enc_pub = load_keys()

    if pub:
        print("\nYOUR WALLET ADDRESS:")
        print(pub)

    if enc_pub:
        print("\nYOUR ENCRYPTION ADDRESS:")
        print(enc_pub)
    else:
        print("\nEncryption key missing. Run option 8.")


def derive_message_key(private_key, recipient_encryption_public_key):
    """
    Creates a shared encryption key using X25519.
    """
    recipient_pub = X25519PublicKey.from_public_bytes(
        base64.b64decode(recipient_encryption_public_key)
    )

    shared_secret = private_key.exchange(recipient_pub)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"PRYME encrypted blockchain message"
    ).derive(shared_secret)

    return base64.urlsafe_b64encode(derived_key)


def encrypt_message(message, encryption_private_key, recipient_encryption_public_key):
    """
    Encrypts a short message before storing it in blockchain.
    """
    key = derive_message_key(encryption_private_key, recipient_encryption_public_key)
    return Fernet(key).encrypt(message.encode()).decode()


def decrypt_message(ciphertext, encryption_private_key, sender_encryption_public_key):
    """
    Decrypts message using local private encryption key and sender public encryption key.
    """
    try:
        key = derive_message_key(encryption_private_key, sender_encryption_public_key)
        return Fernet(key).decrypt(ciphertext.encode()).decode()
    except:
        return None


def read_limited_message():
    """
    Reads a message with strict 200 character limit.
    """
    print(f"\nMessage max length: {MAX_MESSAGE_LENGTH} characters")
    print("Type message:")
    print(f"0/{MAX_MESSAGE_LENGTH}> ", end="", flush=True)

    text = ""

    if os.name == "nt":
        import msvcrt

        while True:
            ch = msvcrt.getwch()

            if ch in ("\r", "\n"):
                print()
                break

            if ch == "\b":
                if text:
                    text = text[:-1]
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue

            if len(text) >= MAX_MESSAGE_LENGTH:
                continue

            text += ch
            sys.stdout.write(ch)
            sys.stdout.flush()

        print(f"Length: {len(text)}/{MAX_MESSAGE_LENGTH}")
        return text.strip()

    text = input("> ")[:MAX_MESSAGE_LENGTH]
    print(f"Length: {len(text)}/{MAX_MESSAGE_LENGTH}")
    return text.strip()


def message_id(block_index, tx):
    """
    Creates a stable local ID for read/unread inbox state.
    This does not affect blockchain.
    """
    raw = json.dumps({
        "block": block_index,
        "type": tx.get("type"),
        "from": tx.get("from"),
        "to": tx.get("to"),
        "encrypted_message": tx.get("encrypted_message"),
        "timestamp": tx.get("timestamp")
    }, sort_keys=True)

    import hashlib
    return hashlib.sha256(raw.encode()).hexdigest()


def load_read_messages():
    """
    Loads local list of messages already read by this wallet.
    """
    data = load_json(READ_MESSAGES_FILE, {})
    data.setdefault("read", [])
    return data


def save_read_messages(data):
    """
    Saves local read-state.
    Blockchain is not changed.
    """
    save_json(READ_MESSAGES_FILE, data)


def mark_message_read(mid):
    """
    Marks message as read locally.
    """
    data = load_read_messages()

    if mid not in data["read"]:
        data["read"].append(mid)
        save_read_messages(data)


def calculate_balance(pub):
    chain = get("/chain")

    if not chain:
        return None

    total = 0.0

    for block in chain:
        for tx in block.get("transactions", []):
            if tx.get("type") == "MINE_PRIME":
                if tx.get("owner_public_key") == pub:
                    total += float(tx.get("reward", 0))

            elif tx.get("type") == "TRANSFER":
                if tx.get("from") == pub:
                    total -= float(tx.get("amount", 0))
                if tx.get("to") == pub:
                    total += float(tx.get("amount", 0))

    pending = get("/pending")

    if pending:
        for tx in pending:
            if tx.get("type") == "TRANSFER" and tx.get("from") == pub:
                total -= float(tx.get("amount", 0))

    return round(total, 6)


def show_balance():
    _, pub, _, _ = load_keys()

    if not pub:
        return

    bal = calculate_balance(pub)

    if bal is not None:
        print("\nBalance:", bal, "PRYME")


def sign_transfer(tx, private_key):
    """
    Signs TRANSFER transactions.
    Optional encrypted message is signed too.
    """
    msg = {
        "type": tx["type"],
        "from": tx["from"],
        "to": tx["to"],
        "amount": float(tx["amount"]),
        "timestamp": int(tx["timestamp"])
    }

    if "encrypted_message" in tx:
        msg["encrypted_message"] = tx["encrypted_message"]
        msg["sender_encryption_public_key"] = tx["sender_encryption_public_key"]

    raw = json.dumps(msg, sort_keys=True).encode()
    tx["signature"] = base64.b64encode(private_key.sign(raw)).decode()


def sign_message(tx, private_key):
    """
    Signs MESSAGE transactions.
    """
    raw = json.dumps({
        "type": tx["type"],
        "from": tx["from"],
        "to": tx["to"],
        "encrypted_message": tx["encrypted_message"],
        "sender_encryption_public_key": tx["sender_encryption_public_key"],
        "timestamp": int(tx["timestamp"])
    }, sort_keys=True).encode()

    tx["signature"] = base64.b64encode(private_key.sign(raw)).decode()


def send_pryme():
    private_key, pub, encryption_private, encryption_public = load_keys()

    if not private_key:
        return

    to = input("To wallet address: ").strip()

    try:
        amount = float(input("Amount: "))
    except:
        print("Invalid amount.")
        return

    if amount <= 0:
        print("Amount must be positive.")
        return

    bal = calculate_balance(pub)

    if bal is not None and amount > bal:
        print("Not enough balance.")
        return

    tx = {
        "type": "TRANSFER",
        "from": pub,
        "to": to,
        "amount": amount,
        "timestamp": int(time.time())
    }

    add_msg = input("Add encrypted message? y/n: ").strip().lower()

    if add_msg == "y":
        if not encryption_private:
            print("Encryption keys missing.")
            return

        recipient_enc = input("Recipient encryption address: ").strip()
        msg = read_limited_message()

        if msg:
            tx["encrypted_message"] = encrypt_message(
                msg,
                encryption_private,
                recipient_enc
            )
            tx["sender_encryption_public_key"] = encryption_public

    sign_transfer(tx, private_key)

    r = post("/submit", tx)

    if not r:
        return

    if r.status_code == 200:
        print("Transfer sent.")
        print("Status:", r.json().get("status"))
    else:
        print("Rejected:", r.text)


def send_message_only():
    """
    Sends encrypted blockchain message without transferring PRYME.
    """
    private_key, pub, encryption_private, encryption_public = load_keys()

    if not private_key:
        return

    if not encryption_private:
        print("Encryption keys missing.")
        return

    to_wallet = input("To wallet address: ").strip()
    to_encryption = input("Recipient encryption address: ").strip()

    message = read_limited_message()

    if not message:
        print("Empty message cancelled.")
        return

    tx = {
        "type": "MESSAGE",
        "from": pub,
        "to": to_wallet,
        "encrypted_message": encrypt_message(
            message,
            encryption_private,
            to_encryption
        ),
        "sender_encryption_public_key": encryption_public,
        "timestamp": int(time.time())
    }

    sign_message(tx, private_key)

    r = post("/submit", tx)

    if not r:
        return

    if r.status_code == 200:
        print("Encrypted message sent.")
    else:
        print("Rejected:", r.text)


def inbox():
    """
    Shows unread incoming encrypted messages.

    Important:
    Messages are not removed from blockchain.
    After reading, they are hidden locally through read_messages.json.
    """
    _, pub, encryption_private, _ = load_keys()

    if not pub:
        return

    if not encryption_private:
        print("Encryption keys missing. Run option 8.")
        return

    chain = get("/chain")

    if not chain:
        return

    read_data = load_read_messages()
    read_ids = set(read_data.get("read", []))

    unread = []

    for block in chain:
        block_index = block.get("index")

        for tx in block.get("transactions", []):
            if tx.get("to") != pub:
                continue

            if not tx.get("encrypted_message"):
                continue

            if tx.get("type") not in ["MESSAGE", "TRANSFER"]:
                continue

            mid = message_id(block_index, tx)

            if mid in read_ids:
                continue

            text = decrypt_message(
                tx.get("encrypted_message"),
                encryption_private,
                tx.get("sender_encryption_public_key", "")
            )

            if not text:
                continue

            unread.append({
                "id": mid,
                "block": block_index,
                "type": tx.get("type"),
                "from": tx.get("from"),
                "amount": tx.get("amount"),
                "message": text,
                "timestamp": tx.get("timestamp")
            })

    if not unread:
        print("\nInbox empty.")
        return

    unread = unread[-INBOX_LIMIT:]

    print(f"\nINBOX — {len(unread)} unread message(s)")
    print("Messages are hidden locally after reading.\n")

    for i, msg in enumerate(unread, start=1):
        print(f"{i}. [{msg['type']}] from {msg['from']} | block {msg['block']}")

    print("\nOpen message number or press Enter to go back.")
    c = input("> ").strip()

    if not c:
        return

    try:
        idx = int(c) - 1
    except:
        print("Invalid number.")
        return

    if idx < 0 or idx >= len(unread):
        print("Invalid number.")
        return

    msg = unread[idx]

    print("\nMESSAGE")
    print("Type:", msg["type"])
    print("Block:", msg["block"])
    print("From:", msg["from"])

    if msg["type"] == "TRANSFER":
        print("Amount:", msg["amount"], "PRYME")

    print("\nText:")
    print(msg["message"])

    mark = input("\nMark as read and hide from inbox? y/n: ").strip().lower()

    if mark == "y":
        mark_message_read(msg["id"])
        print("Message marked as read.")


def history():
    _, pub, encryption_private, _ = load_keys()

    if not pub:
        return

    chain = get("/chain")

    if not chain:
        return

    print("\nHISTORY")
    found = False

    for block in chain:
        for tx in block.get("transactions", []):
            if tx.get("type") == "MINE_PRIME" and tx.get("owner_public_key") == pub:
                print(f"[MINE] +{tx.get('reward', 0)} PRYME | block {block['index']}")
                found = True

            elif tx.get("type") == "TRANSFER":
                if tx.get("from") == pub:
                    print(f"[SEND] -{tx.get('amount')} PRYME | block {block['index']}")
                    found = True

                if tx.get("to") == pub:
                    print(f"[RECV] +{tx.get('amount')} PRYME | block {block['index']}")
                    found = True

                    if tx.get("encrypted_message") and encryption_private:
                        msg = decrypt_message(
                            tx["encrypted_message"],
                            encryption_private,
                            tx.get("sender_encryption_public_key", "")
                        )
                        if msg:
                            print("  Message:", msg)

            elif tx.get("type") == "MESSAGE":
                if tx.get("to") == pub:
                    print(f"[MESSAGE] from {tx.get('from')} | block {block['index']}")
                    found = True

                    if encryption_private:
                        msg = decrypt_message(
                            tx["encrypted_message"],
                            encryption_private,
                            tx.get("sender_encryption_public_key", "")
                        )
                        if msg:
                            print("  Message:", msg)

    pending = get("/pending")

    if pending:
        for tx in pending:
            if tx.get("type") == "TRANSFER" and tx.get("from") == pub:
                print(f"[PENDING SEND] -{tx.get('amount')} PRYME")
                found = True

            if tx.get("type") == "MESSAGE" and tx.get("from") == pub:
                print("[PENDING MESSAGE]")
                found = True

    if not found:
        print("No history yet.")


def node_stats():
    data = get("/stats")

    if not data:
        return

    print("\nNODE STATS")
    print("Height:", data.get("height"))
    print("Pending:", data.get("pending"))
    print("Difficulty:", data.get("difficulty"))
    print("Candidate bits:", data.get("candidate_bits"))
    print("Emission:", data.get("emission"))
    print("Reward:", data.get("current_reward"))
    print("Peers:", len(data.get("peers", [])))


def menu():
    while True:
        print("\nPRYME WALLET")
        print("1. Create wallet")
        print("2. Show address")
        print("3. Balance")
        print("4. History")
        print("5. Send PRYME")
        print("6. Send encrypted message")
        print("7. Inbox")
        print("8. Node stats")
        print("9. Add encryption keys to old wallet")
        print("10. Exit")

        c = input("> ")

        if c == "1":
            create_wallet()
        elif c == "2":
            show_address()
        elif c == "3":
            show_balance()
        elif c == "4":
            history()
        elif c == "5":
            send_pryme()
        elif c == "6":
            send_message_only()
        elif c == "7":
            inbox()
        elif c == "8":
            node_stats()
        elif c == "9":
            ensure_encryption_keys()
        elif c == "10":
            break
        else:
            print("Unknown command.")


if __name__ == "__main__":
    menu()
