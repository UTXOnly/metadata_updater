# MEATADATA_UPDATER CLI

The MEATADATA_UPDATER CLI is a Python script that queries and updates events on Nostr relays. It can be used to check for outdated events and rebroadcast the latest event to the relays found to have old `kind 0` events.

## Features

- Queries online Nostr relays for events.
- Identifies relays with outdated events.
- Rebroadcasts the latest event to relays with outdated events.

## Requirements

- Python 3.7+
- The following Python libraries:
  - `argparse`
  - `asyncio`
  - `concurrent.futures`
  - `hashlib`
  - `json`
  - `logging`
  - `time`
  - `requests`
  - `secp256k1`
  - `uvloop`
  - `websockets`

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/yourusername/noteupdater-cli.git
    cd METADATA_UPDATER
    ```

2. Install the required Python libraries:

    ```sh
    pip install -r requirements.txt
    ```

## Usage

Run the script with a public key hex to query for old kind 0 events:

```sh
python3 update_meta.py <public_key_hex_to_scan_+_update>
