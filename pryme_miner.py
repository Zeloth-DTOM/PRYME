import json, os, time, hashlib, base64, requests, random
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CONFIG_FILE = "config.json"
DEFAULT_PORT = 5001
DEFAULT_LOCAL_NODE = f"http://127.0.0.1:{DEFAULT_PORT}"

KEY_FILE = "wallet_keys.json"
STATE_FILE = "miner_state.json"

STATUS_INTERVAL = 30
CHALLENGE_CHECK_EVERY = 1000
NETWORK_CHECK_INTERVAL = 5

POWER = {
    "low": 0.02,
    "medium": 0.005,
    "high": 0.001
}

SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def sha256(x):
    return hashlib.sha256(x.encode()).hexdigest()


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

    This keeps old local behavior but allows packaged miners to use seed_url.
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


def load_keys():
    keys = load_json(KEY_FILE, None)
    if not keys:
        print("No wallet_keys.json. Create wallet first.")
        return None, None

    private_key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(keys["private_key"])
    )

    return private_key, keys["public_key"]


def load_state():
    s = load_json(STATE_FILE, {})
    s.setdefault("nonce", random.randint(0, 10_000_000))
    s.setdefault("checked", 0)
    s.setdefault("hits", 0)
    s.setdefault("accepted", 0)
    s.setdefault("rejected", 0)
    s.setdefault("challenge", "")
    s.setdefault("power", "medium")
    s.setdefault("node_index", 0)

    if len(NODES) > 0:
        s["node_index"] = int(s.get("node_index", 0)) % len(NODES)
    else:
        s["node_index"] = 0

    return s


def current_node(state):
    return NODES[state["node_index"] % len(NODES)]


def switch_node(state):
    state["node_index"] = (state["node_index"] + 1) % len(NODES)
    save_json(STATE_FILE, state)


def get_stats(state):
    for _ in range(len(NODES)):
        node = current_node(state)
        try:
            r = requests.get(node + "/stats", timeout=5)
            d = r.json()
            return d, node
        except:
            switch_node(state)

    return None, None


def network_ready(state):
    stats, node = get_stats(state)

    if not stats:
        return False, None, 0

    peers = len(stats.get("peers", []))
    return peers > 0, node, peers


def wait_for_network(state):
    while True:
        ready, node, peers = network_ready(state)

        if ready:
            print(f"Network ready | node={node} | peers={peers}")
            return True

        print(f"Mining paused: node isolated | peers={peers}")
        print("Tried nodes:", ", ".join(NODES))
        time.sleep(NETWORK_CHECK_INTERVAL)


def get_challenge(state):
    for _ in range(len(NODES)):
        node = current_node(state)
        try:
            ready, _, peers = network_ready(state)

            if not ready:
                print(f"Node isolated. Peers={peers}. Challenge rejected.")
                return None

            r = requests.get(node + "/challenge", timeout=5)
            d = r.json()

            return {
                "node": node,
                "challenge": d["challenge"],
                "difficulty": int(d["difficulty"]),
                "candidate_bits": int(d.get("candidate_bits", 256)),
                "reward": float(d.get("reward", 0)),
                "height": int(d.get("height", 0)),
                "work": int(d.get("work", 0))
            }
        except:
            switch_node(state)

    print("Node unavailable.")
    print("Tried nodes:", ", ".join(NODES))
    return None


def candidate(challenge, nonce, public_key, bits):
    raw = f"{challenge}:{public_key}:{nonce}"
    pow_hash = sha256(raw)

    byte_len = (bits + 7) // 8
    digest = hashlib.shake_256(raw.encode()).digest(byte_len)

    num = int.from_bytes(digest, "big")
    num |= (1 << (bits - 1))
    num |= 1

    return pow_hash, num


def is_prime(n):
    if n < 2:
        return False

    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    for a in SMALL_PRIMES:
        if a >= n:
            continue

        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                break
        else:
            return False

    return True


def sign(tx, private_key):
    msg = json.dumps({
        "type": tx["type"],
        "challenge": tx["challenge"],
        "nonce": str(tx["nonce"]),
        "hash": tx["hash"],
        "candidate": str(tx["candidate"]),
        "owner_public_key": tx["owner_public_key"]
    }, sort_keys=True).encode()

    sig = private_key.sign(msg)
    tx["signature"] = base64.b64encode(sig).decode()


def submit(tx, state):
    ready, _, peers = network_ready(state)

    if not ready:
        return None, f"mining_blocked_isolated_peers_{peers}", None

    for _ in range(len(NODES)):
        node = current_node(state)
        try:
            r = requests.post(node + "/submit", json=tx, timeout=10)
            return r.status_code, r.text, node
        except:
            switch_node(state)

    return None, "network_error", None


def refresh_if_needed(state, challenge, difficulty, bits, reward):
    info = get_challenge(state)

    if not info:
        return challenge, difficulty, bits, reward, False

    if info["challenge"] != challenge:
        return (
            info["challenge"],
            info["difficulty"],
            info["candidate_bits"],
            info["reward"],
            True
        )

    return challenge, difficulty, bits, reward, False


def get_power():
    s = load_json(STATE_FILE, {})
    return s.get("power", "medium")


def mine():
    private_key, public_key = load_keys()

    if not private_key:
        return

    state = load_state()

    wait_for_network(state)

    info = get_challenge(state)

    if not info:
        return

    challenge = info["challenge"]
    difficulty = info["difficulty"]
    bits = info["candidate_bits"]
    reward = info["reward"]

    if state["challenge"] != challenge:
        state["nonce"] = random.randint(0, 10_000_000)
        state["challenge"] = challenge

    nonce = int(state["nonce"])

    print("\nPRYME MINER")
    print("Node:", info["node"])
    print("Height:", info["height"])
    print("Work:", info["work"])
    print("Power:", state.get("power", "medium"))
    print("Difficulty:", difficulty)
    print("Candidate bits:", bits)
    print("Reward:", reward)
    print("Ctrl+C to stop\n")

    started = time.time()
    last_status = time.time()
    last_network_check = time.time()

    try:
        while True:
            now = time.time()

            if now - last_network_check >= NETWORK_CHECK_INTERVAL:
                ready, node, peers = network_ready(state)

                if not ready:
                    print(f"Mining paused: node isolated | peers={peers}")
                    save_json(STATE_FILE, state)
                    wait_for_network(state)

                    info = get_challenge(state)
                    if not info:
                        continue

                    challenge = info["challenge"]
                    difficulty = info["difficulty"]
                    bits = info["candidate_bits"]
                    reward = info["reward"]
                    nonce = random.randint(0, 10_000_000)
                    state["challenge"] = challenge
                    state["nonce"] = nonce

                last_network_check = now

            h, num = candidate(challenge, nonce, public_key, bits)
            state["checked"] += 1

            if h.startswith("0" * difficulty) and is_prime(num):
                state["hits"] += 1

                tx = {
                    "type": "MINE_PRIME",
                    "challenge": challenge,
                    "nonce": str(nonce),
                    "hash": h,
                    "candidate": str(num),
                    "owner_public_key": public_key
                }

                sign(tx, private_key)

                status, msg, used_node = submit(tx, state)

                if status == 200:
                    state["accepted"] += 1

                    try:
                        data = json.loads(msg)
                        print(
                            f"✔ block accepted | "
                            f"block={data.get('block')} | "
                            f"reward={data.get('reward')} | "
                            f"tx={data.get('tx_count')} | "
                            f"work={data.get('work')}"
                        )
                    except:
                        print("✔ block accepted")

                    info = get_challenge(state)

                    if info:
                        challenge = info["challenge"]
                        difficulty = info["difficulty"]
                        bits = info["candidate_bits"]
                        reward = info["reward"]
                        nonce = random.randint(0, 10_000_000)
                        state["challenge"] = challenge
                else:
                    state["rejected"] += 1
                    print("Rejected:", msg)

                    challenge, difficulty, bits, reward, changed = refresh_if_needed(
                        state, challenge, difficulty, bits, reward
                    )

                    if changed:
                        nonce = random.randint(0, 10_000_000)
                        state["challenge"] = challenge

            nonce += 1
            state["nonce"] = nonce

            if nonce % CHALLENGE_CHECK_EVERY == 0:
                challenge, difficulty, bits, reward, changed = refresh_if_needed(
                    state, challenge, difficulty, bits, reward
                )

                if changed:
                    nonce = random.randint(0, 10_000_000)
                    state["challenge"] = challenge

            now = time.time()

            if now - last_status >= STATUS_INTERVAL:
                speed = state["checked"] / max(1, now - started)

                print(
                    f"hashes={state['checked']} | "
                    f"hits={state['hits']} | "
                    f"accepted={state['accepted']} | "
                    f"rejected={state['rejected']} | "
                    f"speed={speed:.1f}/s | "
                    f"diff={difficulty} | "
                    f"bits={bits}"
                )

                save_json(STATE_FILE, state)
                last_status = now

            mode = get_power()
            pause = POWER.get(mode, POWER["medium"])
            time.sleep(pause)

    except KeyboardInterrupt:
        save_json(STATE_FILE, state)
        print("\nMiner stopped safely.")


def show_stats():
    print(json.dumps(load_state(), indent=2))


def set_power():
    s = load_state()

    print("\nPOWER MODE")
    print("1. Low")
    print("2. Medium")
    print("3. High")

    c = input("> ")

    if c == "1":
        s["power"] = "low"
    elif c == "2":
        s["power"] = "medium"
    elif c == "3":
        s["power"] = "high"
    else:
        print("Unknown mode.")
        return

    save_json(STATE_FILE, s)
    print("Power set to:", s["power"])


def reset_nonce():
    s = load_state()
    s["nonce"] = random.randint(0, 10_000_000)
    save_json(STATE_FILE, s)
    print("Nonce reset.")


def menu():
    while True:
        print("\nPRYME MINER")
        print("1. Start")
        print("2. Stats")
        print("3. Power mode")
        print("4. Reset nonce")
        print("5. Exit")

        c = input("> ")

        if c == "1":
            mine()
        elif c == "2":
            show_stats()
        elif c == "3":
            set_power()
        elif c == "4":
            reset_nonce()
        elif c == "5":
            break
        else:
            print("Unknown command.")


if __name__ == "__main__":
    menu()
