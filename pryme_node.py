# PRYME NODE v15.2
# Protected protocol node:
# - P2P bootstrap
# - peer discovery
# - strict chain validation
# - protocol hash protection
# - tx/block broadcast
# - cumulative work sync
# - encrypted blockchain messages
# - transfer transactions with optional encrypted messages
# - external validator voting before local block acceptance
# - auto public IP detection
# - config-based seed node setup

import json, os, time, hashlib, base64, sys, threading, requests

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sympy import isprime


app = Flask(__name__)

CONFIG_FILE = "config.json"
DEFAULT_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5001


def sha256(x):
    return hashlib.sha256(x.encode()).hexdigest()


def load_json(file, default):
    """
    Safely loads JSON from disk.
    If the file is missing or corrupted, returns default.
    """
    if not os.path.exists(file):
        return default

    try:
        with open(file, "r") as f:
            return json.load(f)
    except:
        return default


def save_json(file, data):
    """
    Saves JSON to disk in a readable format.
    """
    with open(file, "w") as f:
        json.dump(data, f, indent=2)


def detect_public_ip():
    """
    Tries to detect external public IP automatically.
    If detection fails, returns None.
    """
    services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com"
    ]

    for service in services:
        try:
            ip = requests.get(service, timeout=5).text.strip()

            if ip and "." in ip and len(ip) < 64:
                return ip
        except:
            pass

    return None


def load_config():
    """
    Loads node configuration.

    public_url:
    - "auto" means the node tries to detect public IP automatically.
    - manual example: "http://123.123.123.123:5001"

    seed_url:
    - primary bootstrap node.
    - your main first node can leave this empty.
    - other nodes can use your first node here.

    seeds:
    - optional additional seed nodes.
    """
    default = {
        "host": "0.0.0.0",
        "port": DEFAULT_PORT,
        "public_url": "auto",
        "seed_url": "",
        "seeds": []
    }

    cfg = load_json(CONFIG_FILE, default)
    changed = False

    for key, value in default.items():
        if key not in cfg:
            cfg[key] = value
            changed = True

    cfg["host"] = str(cfg.get("host", "0.0.0.0"))
    cfg["port"] = int(cfg.get("port", DEFAULT_PORT))

    if cfg.get("public_url") in ["auto", "", None]:
        public_ip = detect_public_ip()

        if public_ip:
            cfg["public_url"] = f"http://{public_ip}:{cfg['port']}"
        else:
            cfg["public_url"] = f"http://127.0.0.1:{cfg['port']}"

        changed = True

    cfg["public_url"] = str(cfg["public_url"]).rstrip("/")

    if cfg.get("seed_url") is None:
        cfg["seed_url"] = ""
        changed = True

    cfg["seed_url"] = str(cfg.get("seed_url", "")).rstrip("/")
    cfg["seeds"] = [s.rstrip("/") for s in cfg.get("seeds", []) if s]

    if changed or not os.path.exists(CONFIG_FILE):
        save_json(CONFIG_FILE, cfg)

    return cfg


CONFIG = load_config()

HOST = CONFIG.get("host", "0.0.0.0")
PORT = int(CONFIG.get("port", DEFAULT_PORT))
SELF_URL = CONFIG["public_url"]

CHAIN_FILE = f"chain_{PORT}.json"
PENDING_FILE = f"pending_{PORT}.json"
PEERS_FILE = f"peers_{PORT}.json"


BUILTIN_SEEDS = [
    # Optional hardcoded permanent seed node, for example:
    # "http://YOUR_PUBLIC_IP:5001"
]


MAX_SUPPLY = 1_000_000_000
TARGET_BLOCK_TIME = 120
HALVING_INTERVAL = 1_314_000
BASE_REWARD = 380.0

MIN_DIFFICULTY = 4
MAX_DIFFICULTY = 10
DIFFICULTY_WINDOW = 60

START_CANDIDATE_BITS = 256
BITS_STEP_BLOCKS = 250_000
BITS_STEP_SIZE = 32
MAX_CANDIDATE_BITS = 4096

TX_TTL = 300
MAX_TX_PER_BLOCK = 50
PEER_TTL = 3600

MAX_MESSAGE_LENGTH = 200
MAX_ENCRYPTED_SIZE = 800

PROTOCOL_VERSION = "PRYME-v15-mainnet-validator-votes"


PROTOCOL_RULES = {
    "max_supply": MAX_SUPPLY,
    "target_block_time": TARGET_BLOCK_TIME,
    "halving_interval": HALVING_INTERVAL,
    "base_reward": BASE_REWARD,
    "min_difficulty": MIN_DIFFICULTY,
    "max_difficulty": MAX_DIFFICULTY,
    "difficulty_window": DIFFICULTY_WINDOW,
    "start_candidate_bits": START_CANDIDATE_BITS,
    "bits_step_blocks": BITS_STEP_BLOCKS,
    "bits_step_size": BITS_STEP_SIZE,
    "max_candidate_bits": MAX_CANDIDATE_BITS,
    "max_message_length": MAX_MESSAGE_LENGTH,
    "max_encrypted_size": MAX_ENCRYPTED_SIZE,
    "validator_consensus": "external_vote_required",
}

PROTOCOL_HASH = sha256(json.dumps(PROTOCOL_RULES, sort_keys=True))


def all_seeds():
    """
    Returns all known seed nodes.

    Priority:
    1. BUILTIN_SEEDS from code, if ever needed later.
    2. seed_url from config.json.
    3. seeds list from config.json.

    Self URL is ignored.
    Duplicates are removed.
    """
    seeds = []

    for s in BUILTIN_SEEDS:
        s = s.rstrip("/")
        if s and s != SELF_URL and s not in seeds:
            seeds.append(s)

    seed = CONFIG.get("seed_url", "")
    if seed:
        seed = seed.rstrip("/")
        if seed and seed != SELF_URL and seed not in seeds:
            seeds.append(seed)

    for s in CONFIG.get("seeds", []):
        s = s.rstrip("/")
        if s and s != SELF_URL and s not in seeds:
            seeds.append(s)

    return seeds


def load_peers():
    return load_json(PEERS_FILE, {})


def save_peers(peers):
    save_json(PEERS_FILE, peers)


def add_peer(url):
    """
    Adds or updates a peer.
    """
    if not url:
        return False

    url = url.rstrip("/")

    if url == SELF_URL:
        return False

    peers = load_peers()
    peers[url] = {
        "url": url,
        "last_seen": time.time()
    }

    save_peers(peers)
    return True


def get_peers():
    """
    Returns only fresh peers.
    Old peers are removed automatically.
    """
    now = time.time()
    peers = load_peers()
    clean = {}

    for url, data in peers.items():
        if now - data.get("last_seen", 0) < PEER_TTL:
            clean[url] = data

    save_peers(clean)
    return list(clean.keys())


def bootstrap():
    """
    Starts initial peer discovery.
    """
    for seed in all_seeds():
        add_peer(seed)

    sync_peers()
    broadcast_hello()


def sync_peers():
    """
    Downloads peer lists from known peers.
    Only peers with the same protocol hash are accepted.
    """
    for peer in get_peers():
        try:
            r = requests.get(peer + "/peers", timeout=3)
            data = r.json()

            if data.get("protocol_hash") != PROTOCOL_HASH:
                continue

            add_peer(data.get("self"))

            for p in data.get("peers", []):
                add_peer(p)
        except:
            pass


def broadcast_hello():
    """
    Announces this node to known peers.
    """
    for peer in get_peers():
        try:
            requests.post(
                peer + "/hello",
                json={
                    "url": SELF_URL,
                    "protocol_version": PROTOCOL_VERSION,
                    "protocol_hash": PROTOCOL_HASH
                },
                timeout=3
            )
        except:
            pass


def load_chain():
    """
    Loads blockchain from disk.
    Creates genesis block if no chain exists.
    """
    chain = load_json(CHAIN_FILE, [])

    if not chain:
        chain = [{
            "index": 0,
            "timestamp": int(time.time()),
            "previous_hash": "0",
            "transactions": [],
            "difficulty": MIN_DIFFICULTY,
            "candidate_bits": START_CANDIDATE_BITS,
            "protocol": PROTOCOL_VERSION,
            "protocol_hash": PROTOCOL_HASH,
            "hash": "genesis"
        }]

        save_json(CHAIN_FILE, chain)

    return chain


def save_chain(chain):
    save_json(CHAIN_FILE, chain)


def load_pending():
    return load_json(PENDING_FILE, [])


def save_pending(pending):
    save_json(PENDING_FILE, pending)


def clean_pending(pending):
    """
    Removes old unconfirmed transactions.
    """
    now = time.time()
    return [tx for tx in pending if now - tx.get("added_at", now) < TX_TTL]


def tx_id(tx):
    """
    Creates stable transaction ID.
    added_at is local metadata and is not part of identity.
    """
    t = dict(tx)
    t.pop("added_at", None)
    return sha256(json.dumps(t, sort_keys=True))


def verify(pub, sig, msg):
    """
    Verifies Ed25519 signature.
    """
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub))
        key.verify(base64.b64decode(sig), msg.encode())
        return True
    except:
        return False


def block_hash(block):
    """
    Calculates block hash without the hash field itself.
    """
    b = dict(block)
    b.pop("hash", None)
    return sha256(json.dumps(b, sort_keys=True))


def challenge(chain):
    """
    Mining challenge depends on the last block.
    """
    last = chain[-1]
    return sha256(last["hash"] + str(last["index"]))


def candidate_bits_for_height(height):
    bits = START_CANDIDATE_BITS + (height // BITS_STEP_BLOCKS) * BITS_STEP_SIZE
    return min(bits, MAX_CANDIDATE_BITS)


def candidate_bits(chain):
    return candidate_bits_for_height(len(chain))


def candidate(ch, nonce, pub, bits):
    """
    Generates prime candidate from challenge, nonce and public key.
    """
    raw = f"{ch}:{pub}:{nonce}"
    pow_hash = sha256(raw)

    byte_len = (bits + 7) // 8
    digest = hashlib.shake_256(raw.encode()).digest(byte_len)

    num = int.from_bytes(digest, "big")
    num |= (1 << (bits - 1))
    num |= 1

    return pow_hash, num


def current_difficulty(chain):
    """
    Adjusts mining difficulty based on recent block timing.
    """
    if len(chain) < DIFFICULTY_WINDOW + 1:
        return MIN_DIFFICULTY

    recent = chain[-DIFFICULTY_WINDOW:]
    actual = recent[-1]["timestamp"] - recent[0]["timestamp"]
    expected = TARGET_BLOCK_TIME * (len(recent) - 1)

    diff = chain[-1].get("difficulty", MIN_DIFFICULTY)

    if actual < expected * 0.75:
        diff += 1
    elif actual > expected * 1.5:
        diff -= 1

    return max(MIN_DIFFICULTY, min(MAX_DIFFICULTY, diff))


def chain_work(chain):
    """
    Calculates cumulative chain work.
    The chain with more work wins during sync.
    """
    work = 0

    for block in chain[1:]:
        work += 16 ** int(block.get("difficulty", MIN_DIFFICULTY))

    return work


def reward_for_height(height):
    halvings = height // HALVING_INTERVAL
    reward = BASE_REWARD / (2 ** halvings)
    return 0 if reward < 0.000001 else reward


def current_reward(chain):
    return reward_for_height(len(chain))


def total_emission(chain):
    total = 0.0

    for block in chain:
        for tx in block.get("transactions", []):
            if tx.get("type") == "MINE_PRIME":
                total += float(tx.get("reward", 0))

    return total


def balance(addr, chain):
    """
    Calculates confirmed wallet balance.
    MESSAGE transactions do not affect balance.
    """
    total = 0.0

    for block in chain:
        for tx in block.get("transactions", []):
            if tx.get("type") == "MINE_PRIME":
                if tx.get("owner_public_key") == addr:
                    total += float(tx.get("reward", 0))

            elif tx.get("type") == "TRANSFER":
                if tx.get("from") == addr:
                    total -= float(tx.get("amount", 0))
                if tx.get("to") == addr:
                    total += float(tx.get("amount", 0))

    return total


def pending_spent(addr, pending):
    """
    Calculates amount already reserved by pending transfers.
    MESSAGE transactions are ignored because they do not spend PRYME.
    """
    return sum(
        float(tx["amount"])
        for tx in pending
        if tx.get("type") == "TRANSFER" and tx.get("from") == addr
    )


def valid_encrypted_payload(tx):
    """
    Validates encrypted message payload size.
    The original user message limit is 200 characters.
    The encrypted payload is technically larger, so we limit ciphertext size.
    """
    msg = tx.get("encrypted_message")

    if msg is None:
        return True

    if not isinstance(msg, str):
        return False

    if len(msg) == 0:
        return False

    if len(msg) > MAX_ENCRYPTED_SIZE:
        return False

    return True


def mining_message(tx):
    """
    Stable signing payload for mining transactions.
    """
    return json.dumps({
        "type": tx["type"],
        "challenge": tx["challenge"],
        "nonce": str(tx["nonce"]),
        "hash": tx["hash"],
        "candidate": str(tx["candidate"]),
        "owner_public_key": tx["owner_public_key"]
    }, sort_keys=True)


def transfer_message(tx):
    """
    Stable signing payload for transfer transactions.
    Optional encrypted message fields are signed too.
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

    return json.dumps(msg, sort_keys=True)


def message_message(tx):
    """
    Stable signing payload for message-only transactions.
    """
    return json.dumps({
        "type": tx["type"],
        "from": tx["from"],
        "to": tx["to"],
        "encrypted_message": tx["encrypted_message"],
        "sender_encryption_public_key": tx["sender_encryption_public_key"],
        "timestamp": int(tx["timestamp"])
    }, sort_keys=True)


def validate_mine(tx, chain):
    """
    Validates proof-of-work prime mining transaction.
    """
    try:
        diff = current_difficulty(chain)
        bits = candidate_bits(chain)

        if tx["challenge"] != challenge(chain):
            return False

        h, num = candidate(
            tx["challenge"],
            tx["nonce"],
            tx["owner_public_key"],
            bits
        )

        if h != tx["hash"]:
            return False

        if str(num) != str(tx["candidate"]):
            return False

        if not h.startswith("0" * diff):
            return False

        if not isprime(num):
            return False

        return verify(
            tx["owner_public_key"],
            tx["signature"],
            mining_message(tx)
        )

    except:
        return False


def validate_transfer(tx, chain, pending):
    """
    Validates PRYME transfer.
    Transfers may optionally include encrypted messages.
    """
    try:
        amount = float(tx["amount"])
        sender = tx["from"]

        if amount <= 0:
            return False

        if sender == tx["to"]:
            return False

        if not valid_encrypted_payload(tx):
            return False

        if "encrypted_message" in tx:
            if "sender_encryption_public_key" not in tx:
                return False

        available = balance(sender, chain) - pending_spent(sender, pending)

        if available < amount:
            return False

        return verify(tx["from"], tx["signature"], transfer_message(tx))

    except:
        return False


def validate_message(tx):
    """
    Validates encrypted message-only transaction.
    This transaction does not move PRYME.
    """
    try:
        if tx.get("type") != "MESSAGE":
            return False

        if not tx.get("from") or not tx.get("to"):
            return False

        if tx.get("from") == tx.get("to"):
            return False

        if not tx.get("encrypted_message"):
            return False

        if not tx.get("sender_encryption_public_key"):
            return False

        if not valid_encrypted_payload(tx):
            return False

        int(tx["timestamp"])

        return verify(tx["from"], tx["signature"], message_message(tx))

    except:
        return False


def validate_user_tx(tx, chain, pending):
    """
    Validates all non-mining user transactions.
    """
    if tx.get("type") == "TRANSFER":
        return validate_transfer(tx, chain, pending)

    if tx.get("type") == "MESSAGE":
        return validate_message(tx)

    return False


def validate_chain_full(chain):
    """
    Full blockchain validation from genesis to tip.
    """
    if not chain:
        return False

    genesis = chain[0]

    if genesis.get("hash") != "genesis":
        return False

    if genesis.get("protocol_hash") != PROTOCOL_HASH:
        return False

    test_chain = [genesis]
    emitted = 0.0

    for i in range(1, len(chain)):
        block = chain[i]

        if block.get("protocol") != PROTOCOL_VERSION:
            return False

        if block.get("protocol_hash") != PROTOCOL_HASH:
            return False

        if block.get("index") != i:
            return False

        if block.get("previous_hash") != test_chain[-1].get("hash"):
            return False

        if block_hash(block) != block.get("hash"):
            return False

        expected_diff = current_difficulty(test_chain)
        expected_bits = candidate_bits(test_chain)

        if int(block.get("difficulty")) != expected_diff:
            return False

        if int(block.get("candidate_bits")) != expected_bits:
            return False

        txs = block.get("transactions", [])

        if not txs:
            return False

        mine_txs = [tx for tx in txs if tx.get("type") == "MINE_PRIME"]

        if len(mine_txs) != 1:
            return False

        mining_tx = mine_txs[0]

        expected_reward = reward_for_height(len(test_chain))

        if emitted >= MAX_SUPPLY:
            expected_reward = 0
        elif emitted + expected_reward > MAX_SUPPLY:
            expected_reward = MAX_SUPPLY - emitted

        expected_reward = round(expected_reward, 6)

        if round(float(mining_tx.get("reward", -1)), 6) != expected_reward:
            return False

        mining_copy = dict(mining_tx)
        mining_copy.pop("reward", None)
        mining_copy.pop("added_at", None)

        if not validate_mine(mining_copy, test_chain):
            return False

        temp_pending = []

        for tx in txs:
            if tx.get("type") == "TRANSFER":
                if not validate_transfer(tx, test_chain, temp_pending):
                    return False
                temp_pending.append(tx)

            elif tx.get("type") == "MESSAGE":
                if not validate_message(tx):
                    return False

            elif tx.get("type") == "MINE_PRIME":
                pass

            else:
                return False

        emitted += expected_reward
        test_chain.append(block)

    return emitted <= MAX_SUPPLY


def select_valid_user_transactions(chain, pending):
    """
    Selects valid pending TRANSFER and MESSAGE transactions for the next block.
    """
    selected = []
    temp_pending = []

    for tx in clean_pending(pending):
        if tx.get("type") == "TRANSFER":
            if validate_transfer(tx, chain, temp_pending):
                selected.append(tx)
                temp_pending.append(tx)

        elif tx.get("type") == "MESSAGE":
            if validate_message(tx):
                selected.append(tx)

        if len(selected) >= MAX_TX_PER_BLOCK:
            break

    return selected


def remove_confirmed(pending, confirmed):
    confirmed_ids = set(tx_id(tx) for tx in confirmed)
    return [tx for tx in pending if tx_id(tx) not in confirmed_ids]


def required_validator_votes():
    """
    Defines how many external validator approvals are required.

    Small network rule:
    - 0 peers: block cannot be accepted because 0 external votes are possible.
    - 1-2 peers: 1 external validator vote is enough.
    - 3+ peers: majority of known peers is required.
    """
    peer_count = len(get_peers())

    if peer_count == 0:
        return 1

    if peer_count < 3:
        return 1

    return (peer_count // 2) + 1


def request_validator_votes(block):
    """
    Sends the candidate block to external peers for validation.

    The local node's own vote is never counted.
    Only other peers can approve the block.
    """
    votes = 0

    for peer in get_peers():
        try:
            r = requests.post(
                peer + "/validate_block_candidate",
                json=block,
                timeout=5
            )

            data = r.json()

            if data.get("ok") is True:
                votes += 1

        except:
            pass

    return votes


def create_block(mining_tx):
    """
    Creates a new block from a valid mining transaction
    and selected pending user transactions.

    Before saving the block, this node must receive external validator approval.
    """
    chain = load_chain()
    pending = clean_pending(load_pending())

    if not validate_mine(mining_tx, chain):
        return None

    user_txs = select_valid_user_transactions(chain, pending)

    emitted = total_emission(chain)

    if emitted >= MAX_SUPPLY:
        mining_tx["reward"] = 0
    else:
        reward = current_reward(chain)

        if emitted + reward > MAX_SUPPLY:
            reward = MAX_SUPPLY - emitted

        mining_tx["reward"] = round(reward, 6)

    block = {
        "index": len(chain),
        "timestamp": int(time.time()),
        "previous_hash": chain[-1]["hash"],
        "difficulty": current_difficulty(chain),
        "candidate_bits": candidate_bits(chain),
        "protocol": PROTOCOL_VERSION,
        "protocol_hash": PROTOCOL_HASH,
        "transactions": [mining_tx] + user_txs,
        "hash": ""
    }

    block["hash"] = block_hash(block)

    candidate_chain = chain + [block]

    if not validate_chain_full(candidate_chain):
        return None

    required_votes = required_validator_votes()
    votes = request_validator_votes(block)

    if votes < required_votes:
        print(
            f"[CONSENSUS] block rejected: "
            f"votes={votes}, required={required_votes}, peers={len(get_peers())}"
        )
        return None

    print(
        f"[CONSENSUS] block approved: "
        f"votes={votes}, required={required_votes}"
    )

    save_chain(candidate_chain)
    save_pending(remove_confirmed(pending, user_txs))
    broadcast_block(block)

    return block


def broadcast_tx(tx):
    """
    Broadcasts pending transaction to peers.
    """
    for peer in get_peers():
        try:
            requests.post(peer + "/new_transaction", json=tx, timeout=2)
        except:
            pass


def broadcast_block(block):
    """
    Broadcasts accepted block to peers.
    """
    for peer in get_peers():
        try:
            requests.post(peer + "/new_block", json=block, timeout=2)
        except:
            pass


def sync_chain():
    """
    Syncs blockchain using cumulative work rule.
    """
    local = load_chain()
    local_work = chain_work(local)

    for peer in get_peers():
        try:
            other = requests.get(peer + "/chain", timeout=5).json()

            if chain_work(other) > local_work and validate_chain_full(other):
                print("[SYNC] adopted stronger chain from", peer)
                local = other
                local_work = chain_work(other)

        except:
            pass

    save_chain(local)


def sync_mempool():
    """
    Syncs pending TRANSFER and MESSAGE transactions from peers.
    """
    local = clean_pending(load_pending())
    known = set(tx_id(tx) for tx in local)
    chain = load_chain()

    for peer in get_peers():
        try:
            other = requests.get(peer + "/pending", timeout=3).json()

            for tx in other:
                tid = tx_id(tx)

                if tid in known:
                    continue

                if validate_user_tx(tx, chain, local):
                    local.append(tx)
                    known.add(tid)

        except:
            pass

    save_pending(clean_pending(local))


def sync_loop():
    """
    Background network loop.
    """
    while True:
        time.sleep(10)

        sync_peers()
        broadcast_hello()
        sync_chain()
        sync_mempool()


@app.route("/challenge")
def api_challenge():
    chain = load_chain()

    return jsonify({
        "challenge": challenge(chain),
        "difficulty": current_difficulty(chain),
        "candidate_bits": candidate_bits(chain),
        "height": len(chain),
        "max_supply": MAX_SUPPLY,
        "emission": round(total_emission(chain), 6),
        "reward": round(current_reward(chain), 6),
        "work": chain_work(chain),
        "protocol": PROTOCOL_VERSION,
        "protocol_hash": PROTOCOL_HASH
    })


@app.route("/submit", methods=["POST"])
def api_submit():
    tx = request.get_json()
    chain = load_chain()
    pending = clean_pending(load_pending())

    if not tx:
        return jsonify({"status": "empty_tx"}), 400

    if tx.get("type") in ["TRANSFER", "MESSAGE"]:
        if not validate_user_tx(tx, chain, pending):
            return jsonify({"status": "rejected"}), 400

        tx["added_at"] = time.time()

        if tx_id(tx) not in set(tx_id(t) for t in pending):
            pending.append(tx)
            save_pending(pending)
            broadcast_tx(tx)

        return jsonify({"status": "pending"})

    if tx.get("type") == "MINE_PRIME":
        block = create_block(tx)

        if not block:
            return jsonify({"status": "rejected"}), 400

        return jsonify({
            "status": "accepted",
            "block": block["index"],
            "reward": tx.get("reward", 0),
            "tx_count": len(block["transactions"]),
            "difficulty": block["difficulty"],
            "candidate_bits": block["candidate_bits"],
            "work": chain_work(load_chain())
        })

    return jsonify({"status": "unknown_tx"}), 400


@app.route("/new_transaction", methods=["POST"])
def api_new_transaction():
    tx = request.get_json()
    chain = load_chain()
    pending = clean_pending(load_pending())

    if not tx:
        return jsonify({"ok": False})

    if tx.get("type") not in ["TRANSFER", "MESSAGE"]:
        return jsonify({"ok": False})

    if not validate_user_tx(tx, chain, pending):
        return jsonify({"ok": False})

    tx.setdefault("added_at", time.time())

    if tx_id(tx) not in set(tx_id(t) for t in pending):
        pending.append(tx)
        save_pending(pending)

    return jsonify({"ok": True})


@app.route("/validate_block_candidate", methods=["POST"])
def api_validate_block_candidate():
    """
    External validator endpoint.

    A peer sends us a candidate block.
    We validate it against our current chain.
    If valid, we return ok=True.

    This does not save the block.
    It only gives a validation vote.
    """
    block = request.get_json()
    chain = load_chain()

    if not block:
        return jsonify({"ok": False, "reason": "empty_block"})

    if block.get("protocol_hash") != PROTOCOL_HASH:
        return jsonify({"ok": False, "reason": "wrong_protocol"})

    if block.get("index") != len(chain):
        return jsonify({"ok": False, "reason": "wrong_height"})

    candidate_chain = chain + [block]

    if validate_chain_full(candidate_chain):
        return jsonify({"ok": True})

    return jsonify({"ok": False, "reason": "invalid_block"})


@app.route("/new_block", methods=["POST"])
def api_new_block():
    block = request.get_json()
    chain = load_chain()

    if block.get("protocol_hash") != PROTOCOL_HASH:
        return jsonify({"ok": False, "reason": "wrong_protocol"})

    if block.get("index") == len(chain):
        candidate_chain = chain + [block]

        if validate_chain_full(candidate_chain):
            save_chain(candidate_chain)

            pending = remove_confirmed(
                clean_pending(load_pending()),
                block.get("transactions", [])
            )

            save_pending(pending)

            return jsonify({"ok": True})

    return jsonify({"ok": False})


@app.route("/chain")
def api_chain():
    return jsonify(load_chain())


@app.route("/pending")
def api_pending():
    return jsonify(clean_pending(load_pending()))


@app.route("/peers")
def api_peers():
    return jsonify({
        "self": SELF_URL,
        "peers": get_peers(),
        "protocol": PROTOCOL_VERSION,
        "protocol_hash": PROTOCOL_HASH
    })


@app.route("/hello", methods=["POST"])
def api_hello():
    data = request.get_json()

    if not data:
        return jsonify({"ok": False})

    if data.get("protocol_hash") != PROTOCOL_HASH:
        return jsonify({"ok": False, "reason": "wrong_protocol"})

    if data.get("url"):
        add_peer(data["url"])

    return jsonify({"ok": True})


@app.route("/stats")
def api_stats():
    chain = load_chain()
    pending = clean_pending(load_pending())

    return jsonify({
        "port": PORT,
        "host": HOST,
        "self": SELF_URL,
        "height": len(chain),
        "pending": len(pending),
        "difficulty": current_difficulty(chain),
        "candidate_bits": candidate_bits(chain),
        "target_block_time": TARGET_BLOCK_TIME,
        "max_supply": MAX_SUPPLY,
        "emission": round(total_emission(chain), 6),
        "current_reward": round(current_reward(chain), 6),
        "work": chain_work(chain),
        "peers": get_peers(),
        "validator_votes_required": required_validator_votes(),
        "builtin_seeds": BUILTIN_SEEDS,
        "seed_url": CONFIG.get("seed_url", ""),
        "config_seeds": CONFIG.get("seeds", []),
        "max_message_length": MAX_MESSAGE_LENGTH,
        "max_encrypted_size": MAX_ENCRYPTED_SIZE,
        "protocol": PROTOCOL_VERSION,
        "protocol_hash": PROTOCOL_HASH
    })


if __name__ == "__main__":
    load_chain()
    save_pending(clean_pending(load_pending()))
    bootstrap()

    print(f"PRYME NODE v15.2 on port {PORT}")
    print("HOST:", HOST)
    print("SELF:", SELF_URL)
    print("SEED URL:", CONFIG.get("seed_url", ""))
    print("PROTOCOL:", PROTOCOL_VERSION)
    print("PROTOCOL HASH:", PROTOCOL_HASH)
    print("MAX MESSAGE LENGTH:", MAX_MESSAGE_LENGTH)
    print("MAX ENCRYPTED SIZE:", MAX_ENCRYPTED_SIZE)
    print("VALIDATOR VOTES REQUIRED:", required_validator_votes())
    print("BUILTIN SEEDS:", BUILTIN_SEEDS)
    print("CONFIG SEEDS:", CONFIG.get("seeds", []))
    print("PEERS:", get_peers())
    print("CONFIG FILE:", CONFIG_FILE)

    threading.Thread(target=sync_loop, daemon=True).start()

    app.run(host=HOST, port=PORT)
