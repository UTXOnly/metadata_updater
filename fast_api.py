from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import asyncio
import time
import requests
import uvloop
import websockets
import json
import argparse
import asyncio
import concurrent.futures
import hashlib
import json
import logging
import time
import bech32

import requests
import secp256k1
import uvloop
import websockets

app = FastAPI()

# Serve the static directory (for HTML files, CSS, etc.)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Serve the main HTML page
@app.get("/", response_class=HTMLResponse)
async def read_root():
    file_path = Path("static/index.html")
    return file_path.read_text()



logging.basicConfig(
    filename="./nost_query.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

class NoteUpdater:
    def __init__(self, pubkey_to_query) -> None:
        self.events_found = []
        self.good_relays = []
        self.bad_relays = []
        self.updated_relays = []
        self.unreachable_relays = []
        self.pubkey_to_query = pubkey_to_query
        self.timestamp_set = set()
        self.high_time = 1
        self.all_good_relays = {}
        self.relay_event_pair = {}
        self.old_relays = []
        self.latest_note = ""
        self.return_message = []

    def print_color(self, text, color):
        print(f"\033[1;{color}m{text}\033[0m")


    def bech32_to_hex(self, npub):
        # Remove the 'npub' prefix
        hrp, data = bech32.bech32_decode(npub)
        # Decode the data part into bytes
        decoded_bytes = bech32.convertbits(data, 5, 8, False)
        # Convert bytes to hex
        return bytes(decoded_bytes).hex()

    def process_pubkey(self):
        # Check if the pubkey starts with 'npub'
        if self.pubkey_to_query.startswith("npub"):
            # Convert the bech32 npub to hex
            hex_pubkey = self.bech32_to_hex(self.pubkey_to_query)
            print(f"Converted npub to hex: {hex_pubkey}")
            self.pubkey_to_query = hex_pubkey
        else:
            # Assume it's already a hex value
            print(f"Hex value provided: {self.pubkey_to_query}")

    def sign_event_id(self, event_id: str, private_key_hex: str) -> str:
        private_key = secp256k1.PrivateKey(bytes.fromhex(private_key_hex))
        sig = private_key.schnorr_sign(
            bytes.fromhex(event_id), bip340tag=None, raw=True
        )
        return sig.hex()

    def _get_online_relays(self):
        URL = "https://api.nostr.watch/v1/online"
        response = requests.get(URL, timeout=5)

        if response.status_code == 200:
            data = response.json()
            items_list = []
            for item in data:
                items_list.append(item)
            print(f"{len(items_list)} online relays discovered")
        else:
            print("Error: Unable to fetch data from API")
        return items_list

    def calc_event_id(
        self,
        public_key: str,
        created_at: int,
        kind_number: int,
        tags: list,
        content: str,
    ) -> str:
        data = [0, public_key, created_at, kind_number, tags, content]
        data_str = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(data_str.encode("UTF-8")).hexdigest()

    def verify_signature(self, event_id: str, pubkey: str, sig: str) -> bool:
        try:
            pub_key = secp256k1.PublicKey(bytes.fromhex("02" + pubkey), True)
            result = pub_key.schnorr_verify(
                bytes.fromhex(event_id), bytes.fromhex(sig), None, raw=True
            )
            if result:
                logger.debug(f"Verification successful for event: {event_id}")
                return True
            else:
                logger.error(f"Verification failed for event: {event_id}")
                return False
        except (ValueError, TypeError) as e:
            logger.error(f"Error verifying signature for event {event_id}: {e}")
            return False

    async def _send_event_to_relay(self, relay, event_data):
        try:
            async with websockets.connect(relay) as ws:
                logger.info("WebSocket connection created.")

                event_json = json.dumps(("EVENT", event_data))
                await ws.send(event_json)
                logger.info(f"Event sent to {relay}: {event_json}")

                response = await asyncio.wait_for(ws.recv(), timeout=10)
                response_data = json.loads(response)
                print(f"Response data is {response_data}")

        except asyncio.TimeoutError:
            logger.error(f"Timeout waiting for response from {relay}.")
        except websockets.WebSocketException as wse:
            logger.error(f"WebSocket error with {relay}: {wse}")
        except Exception as exc:
            logger.error(f"Error with {relay}: {exc}")

    async def query_relay(self, relay, kinds=None):
        try:
            async with websockets.connect(relay) as ws:
                query_dict = {
                    "kinds": kinds or [0],
                    "limit": 300,
                    "since": 179340343,
                }

                query_dict["authors"] = [self.pubkey_to_query]

                query_ws = json.dumps(("REQ", "5326483051590112", query_dict))

                await ws.send(query_ws)
                logger.info(f"Query sent to relay {relay}: {query_ws}")
                try:
                    response = json.loads(await asyncio.wait_for(ws.recv(), timeout=3))

                    if response[0] == "EVENT":
                        if response[2]["kind"] == 0:
                            self.relay_event_pair[relay] = response
                            return response[2]
                except asyncio.TimeoutError:
                    logger.info("No response within 1 second, continuing...")
                    self.unreachable_relays.append(relay)
        except Exception as exc:
            logger.error(f"Exception is {exc}, error querying {relay}")

    def integrity_check_whole(self):
        for relay in self.relay_event_pair:
            value = self.relay_event_pair[relay]
            note = value[2]
            if (
                note is not None
                and note["pubkey"] == self.pubkey_to_query
                and note["kind"] == 0
            ):
                try:
                    verified = self.verify_signature(
                        note["id"], note["pubkey"], note["sig"]
                    )
                    if verified:
                        self.good_relays.append(relay)
                        self.timestamp_set.add(note["created_at"])
                        self.calculate_latest_event(note)
                        self.all_good_relays[relay] = note["created_at"]
                    else:
                        self.bad_relays.append(relay)
                        logger.info(f"Relay : {relay} is not verified?")
                except Exception as exc:
                    logger.error(f"Error verifying sig: {exc}")

            else:
                self.bad_relays.append(relay)

    async def gather_queries(self):
        self.online_relays = self._get_online_relays()
        tasks = [
            asyncio.create_task(self.query_relay(relay)) for relay in self.online_relays
        ]
        await asyncio.gather(*tasks)

    async def rebroadcast(self, relay):
        try:
            async with websockets.connect(relay) as ws:
                event_json = json.dumps(("EVENT", self.latest_note))
                await ws.send(event_json)
                print(
                    f"Rebroadcasting latest kind 0: {event_json} note to:  \033[1;32m{relay}\033[0m"
                )
                response = json.loads(await asyncio.wait_for(ws.recv(), timeout=3))
                logger.info(f"Event ID is {response[1]}")
                logger.info(f"Realy {relay} returned response {response}")
                if str(response[2]) in ["true", "True"]:
                    self.updated_relays.append(relay)
        except asyncio.TimeoutError:
            logger.error(f"Timeout waiting for response from {relay}.")
        except websockets.WebSocketException as wse:
            logger.error(f"WebSocket error with {relay}: {wse}")
        except Exception as exc:
            logger.error(f"Error rebroadcasting to {relay}: {exc}")

    async def gather_rebroadcast(self):
        tasks = [
            asyncio.create_task(self.rebroadcast(relay)) for relay in self.old_relays
        ]
        await asyncio.gather(*tasks)

    def calculate_latest_event(self, note):
        if note["created_at"] > self.high_time:
            self.high_time = note["created_at"]
            self.latest_note = note


    def calc_old_relays(self):
        print(f"Newest timestamp is: {self.high_time}")
        for relay in self.all_good_relays:
            if self.all_good_relays[relay] < self.high_time:
                message = (
                    f"Relay has old timestamp {relay} : {self.all_good_relays[relay]}"
                )
                self.return_message.append(message)
                print(message)
                self.old_relays.append(relay)
            elif self.all_good_relays[relay] == self.high_time:
                pass

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


# Endpoint to handle the pubkey scan request
@app.post("/scan")
async def handle_pubkey_scan(request: Request):
    # Parse JSON data from request
    data = await request.json()
    pubkey = data.get("pubkey")

    # If pubkey is not provided, return an error
    if not pubkey:
        return JSONResponse(content={"error": "pubkey not provided"}, status_code=400)

    # Start querying relays with the provided pubkey
    updater = NoteUpdater(pubkey)
    updater.process_pubkey()  # Convert npub if needed
    await updater.gather_queries()  # Query relays
    updater.integrity_check_whole()  # Perform integrity checks
    updater.calc_old_relays()  # Calculate old relays

    # Rebroadcast latest note to old relays if needed
    if updater.old_relays:
        await updater.gather_rebroadcast()

    # Prepare the results
    results = {
        "good_relays": updater.good_relays,
        "bad_relays": updater.bad_relays,
        "old_relays": updater.old_relays,
        "updated_relays": updater.updated_relays,
    }

    # Return the results as JSON
    return JSONResponse(content=results)

# Serve the static HTML page (scan results)
@app.get("/results", response_class=HTMLResponse)
async def show_results():
    file_path = Path("static/results.html")
    return file_path.read_text()
