PRYME is an experimental decentralized blockchain network with its own digital currency, a unique mining model, and built-in secure messaging. The project was designed as a compact, understandable, and fully verifiable system where value is created through computation, and trust is replaced by strict mathematical validation.

Unlike traditional solutions, PRYME combines several approaches: proof-of-work, prime number validation, and external block approval by other network participants. This makes the system both structurally simple and technically distinctive.

The network consists of independent nodes. Each node stores a full copy of the blockchain, validates transactions, exchanges data with other participants, and takes part in confirming new blocks. There is no central server — the network exists entirely through node interaction.

Each block in PRYME contains a list of transactions, a reference to the previous block, difficulty parameters, protocol data, and the mining result. All blocks are linked via hashes, so any modification in the past automatically breaks the integrity of the entire chain. This makes the blockchain immutable and resistant to tampering.

PRYME currency is created exclusively through mining. A user can create a wallet, obtain an address, send and receive funds, and participate in block generation. All transactions are cryptographically signed, and the network verifies signatures, balances, and protocol rules before accepting any operation.

A key feature of PRYME is its mining model. It is based not only on finding a valid hash, as in classical systems, but also on generating a prime number. For each new block, a unique challenge is derived from the previous block. The miner iterates through nonce values, producing input data from which both a hash and a numerical candidate are generated.

For a block to be valid, two conditions must be met: the hash must satisfy the current difficulty (start with a certain number of zeros), and the generated number must be prime. This makes PRYME mining a hybrid task that combines classical proof-of-work with mathematical prime verification.

Importantly, the network does not trust the miner. After receiving a block, each node independently recomputes the hash, regenerates the candidate number, verifies its primality, and checks the signature. Only after full validation can a block be accepted.

Network difficulty is dynamic. It automatically adjusts to the block production rate: if blocks are found too quickly, difficulty increases; if too slowly, it decreases. Additionally, the size of candidate numbers grows over time, gradually making mining more computationally intensive.

Block rewards start at a fixed value and decrease over time. The total supply is capped, and once the maximum is reached, no new coins are created. This ensures a predictable economic model within the network.

Another important feature of PRYME is its hybrid validation system. Before a local node accepts a new block, it sends the block to other nodes for validation. The node’s own vote is not counted. In small networks, a single external approval is sufficient, while larger networks require a majority of validator votes. As a result, a block must not only be mined but also approved by other participants.

In case of competing chains (forks), PRYME selects not simply the longest chain, but the one with the greatest cumulative computational work. This allows the network to recover from temporary conflicts and converge on the strongest valid chain.

PRYME also supports secure messaging. Users can send short encrypted messages directly through the blockchain — either independently or attached to transactions. Modern cryptographic methods are used, ensuring that messages are stored in encrypted form and can only be read by the intended recipient. The wallet includes a simple inbox: messages appear upon receipt and are hidden after being read, keeping the interface lightweight.

The PRYME wallet is a lightweight console application that allows users to manage funds, send transactions, read messages, and monitor network status. It uses two types of keys: one for transaction signatures and another for message encryption.

A PRYME node is responsible for maintaining the network: storing the blockchain, validating blocks, synchronizing with peers, broadcasting transactions, and participating in validator voting. Protocol integrity is enforced through a protocol hash — nodes with mismatched rules do not interact.

The PRYME miner connects to a node, retrieves the current challenge, and begins iterating nonce values. It generates candidates, checks them for primality, and submits valid results to the network. Mining automatically pauses if the node becomes isolated, preventing the creation of disconnected chains.

PRYME is built on several core principles: simplicity, full verifiability, fair distribution through computation, mathematically grounded mining, security, and decentralization.

This is not a clone of existing blockchains, but an original architecture with its own design decisions. PRYME is an experimental network that combines proof-of-work, mathematical mining, external validation, and secure communication into a single system.

The project is intended for testing, development, and exploration of new approaches to decentralized systems.


First Node Setup (Bootstrap / Seed Node)

If you are launching PRYME for the first time, you are creating the network.

Find the file:

config.json

If it does not exist — run the node once and it will be created automatically.

Open config.json and set your public address manually:

{
"host": "0.0.0.0",
"port": 5001,
"public_url": "http://YOUR_IP:5001",
"seed_url": "",
"seeds": [],
"node_url": "auto"
}

Example:

{
"host": "0.0.0.0",
"port": 5001,
"public_url": "http://123.123.123.123:5001",
"seed_url": "",
"seeds": [],
"node_url": "auto"
}

Or using DuckDNS:

{
"host": "0.0.0.0",
"port": 5001,
"public_url": "http://yourname.duckdns.org:5001",
"seed_url": "",
"seeds": [],
"node_url": "auto"
}

Make sure your node is accessible from the internet:

• you have a public (white) IP
• port 5001 is open
• no ISP/mobile operator blocking
• firewall allows incoming connections

Test in browser:

http://YOUR_IP:5001/stats

If it opens → your node is working.

Now run:

pryme_node.exe

At first there will be no peers — this is normal.
You are the first node in the network.

To grow the network, share your address:

http://YOUR_IP:5001

Other users only need to edit seed_url in config.json:

{
"host": "0.0.0.0",
"port": 5001,
"public_url": "auto",
"seed_url": "http://YOUR_IP:5001",
"seeds": [],
"node_url": "auto"
}

After that, peer discovery works automatically.

Important:

Mobile internet (4G/5G hotspot) may block incoming connections or change your IP address.

For a stable public seed node, it is recommended to use:

• home internet with port forwarding
or
• VPS server
or
• DuckDNS / dynamic DNS service

After setup, you can:

• share PRYME and grow the network
• run the miner and start mining PRYME
• test transactions and encrypted messages
• build a private decentralized network together

You are not just a user — you are launching the network.
