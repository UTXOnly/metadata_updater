import asyncio
import hashlib
import json
import logging
import secp256k1
import time
import websockets
import requests
import asyncio
import uvloop
import concurrent.futures
import time
from kind4 import Kind4MessageEncoder


logging.basicConfig(
    filename="./nost_query.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class NoteUpdater:
    def __init__(self) -> None:
        self.events_found = []
        self.good_relays = []
        self.bad_relays = []
        self.scanner_pubkey_hex = (
            "5ce5b352f1ef76b1dffc5694dd5b34126137184cc9a7d78cba841c0635e17952"
        )
        self.scanner_privkey_hex = (
            "2b1e4e1f26517dda57458596760bb3bd3bd3717083763166e12983a6421abc18"
        )
        self.pubkey_to_query = (
            "4503baa127bdfd0b054384dc5ba82cb0e2a8367cbdb0629179f00db1a34caacc"#)"b05ec62a98702e0c202759eac905550dd9e4a2af9a3df856159207925b4f1c50"
        )
        self.timestamp_set = set()
        self.high_time = 1
        self.all_good_relays = {}
        self.relay_event_pair = {}
        self.old_relays = []
        self.latest_note = ""
        self.relays_kind4 = [
            "wss://relay.nostpy.lol",
            "wss://nostpy.serverless-nostr.com",
            "wss://damus.io",
            "wss://nostr.fmt.wiz.biz/",
            "wss://nostr-pub.wellorder.net/",
        ]
        self.return_message = []

    def print_color(self, text, color):
        print(f"\033[1;{color}m{text}\033[0m")

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

    def create_event(self, public_key, private_key_hex, enc_cont):
        tags = [["p", self.pubkey_to_query]]
        created_at = int(time.time())
        kind_number = 4
        content = enc_cont
        event_id = self.calc_event_id(
            public_key, created_at, kind_number, tags, content
        )
        signature_hex = self.sign_event_id(event_id, private_key_hex)
        event_data = {
            "id": event_id,
            "pubkey": public_key,
            "kind": kind_number,
            "created_at": created_at,
            "tags": tags,
            "content": content,
            "sig": signature_hex,
        }

        return event_data

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

    async def send_event(self, public_key, private_key_hex, enc_content):
        try:
            event_data = self.create_event(public_key, private_key_hex, enc_content)
            signature_valid = self.verify_signature(
                event_data.get("id"), public_key, event_data.get("sig")
            )
            if signature_valid:
                for ws_relay in self.relays_kind4:
                    try:
                        async with websockets.connect(ws_relay) as ws:
                            logger.info("WebSocket connection created.")

                            event_json = json.dumps(("EVENT", event_data))
                            await ws.send(event_json)
                            logger.info(f"Event sent to {ws_relay}: {event_json}")

                            response = await asyncio.wait_for(ws.recv(), timeout=10)
                            response_data = json.loads(response)
                            logger.info(
                                f"DM response from {ws_relay} is {response_data}"
                            )
                    except asyncio.TimeoutError:
                        logger.error(f"Timeout waiting for response from {ws_relay}.")
                    except websockets.WebSocketException as wse:
                        logger.error(f"WebSocket error with {ws_relay}: {wse}")
                    except Exception as exc:
                        logger.error(f"Error with {ws_relay}: {exc}")

        except Exception as exc:
            logger.error(f"Error creating or processing event: {exc}")

    async def query_relay(self, relay, kinds=None):
        try:
            async with websockets.connect(relay) as ws:
                query_dict = {
                    "kinds": kinds or [0],
                    "limit": 300,
                    "since": 179340343,
                }

                if kinds == [4]:
                    query_dict["tags"] = ["p", self.scanner_pubkey_hex]
                else:
                    query_dict["authors"] = [self.pubkey_to_query]

                query_ws = json.dumps(("REQ", "5326483051590112", query_dict))

                await ws.send(query_ws)
                logger.info(f"Query sent to relay {relay}: {query_ws}")
                try:
                    response = json.loads(await asyncio.wait_for(ws.recv(), timeout=3))

                    if response[0] == "EVENT":
                        if response[2]["kind"] == 0:
                            self.relay_event_pair[relay] = response
                            return
                        else:
                            self.return_event = response[2]["pubkey"]

                except asyncio.TimeoutError:
                    logger.info("No response within 1 second, continuing...")
        except Exception as exc:
            logger.error(f"Exception is {exc}, error querying {relay}")

    async def query_kind4(self):
        tasks = [
            asyncio.create_task(self.query_relay(relay, kinds=[4]))
            for relay in self.relays_kind4
        ]
        await asyncio.gather(*tasks)

    def integrity_check_whole(self):
        for relay in self.relay_event_pair:
            value = self.relay_event_pair[relay]
            note = value[2]
            if (
                note != None
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
                logger.info(
                    f"rebroadcasting latest kind 0: {event_json} note to: {relay}"
                )
                response = json.loads(await asyncio.wait_for(ws.recv(), timeout=3))
                logger.debug(f"response 1 is {response[1]}")
                if response[2] == self.latest_note:
                    print(f"Relay: {relay} now has latest event: {self.latest_note}")
        except Exception as exc:
            logger.error(f"Error rebroadcasting to {relay} : {exc}")

    async def gather_rebroadcast(self):
        tasks = [
            asyncio.create_task(self.rebroadcast(relay)) for relay in self.old_relays
        ]
        await asyncio.gather(*tasks)

    def calculate_latest_event(self, note):
        if note["created_at"] > self.high_time:
            self.high_time = note["created_at"]
            self.latest_note = note

    async def list_old_relays(self, timestamp, relay):
        if timestamp < self.high_time:
            print(f"Realy {relay} had old event")

    def calc_old_relays(self):
        print(f"Newest timestmap is: {self.high_time}")
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


async def main():
    try:
        start_time = time.time()

        update_obj = NoteUpdater()
        update_obj.print_color("Starting to query relays", "34")

        loop = asyncio.get_event_loop()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=200)
        loop.set_default_executor(executor)

        await update_obj.query_kind4()
        await update_obj.gather_queries()

        gather_time = time.time()
        update_obj.print_color(
            f"--- {gather_time - start_time} seconds --- to query relays", "32"
        )

        update_obj.integrity_check_whole()
        logger.info(
            f"Relays that return the corect timestpamp are {update_obj.good_relays}, Relays with bad time stamps are: {update_obj.bad_relays}"
        )

        update_obj.calc_old_relays()
        print(
            f"Bad relays are : {update_obj.bad_relays}, old relays is {update_obj.old_relays}"
        )
        calculate_time = time.time()
        update_obj.print_color(
            f"--- {calculate_time - gather_time} seconds --- to perform calculations",
            "32",
        )
        if update_obj.old_relays:
            await update_obj.gather_rebroadcast()
            rebroadcast_time = time.time()
            update_obj.print_color(
                f"--- {rebroadcast_time - calculate_time} seconds --- to rebroadcast",
                "32",
            )

        final_time = time.time() - start_time
        update_obj.print_color(f"----- {final_time} seconds final time", "32")
        try:
            kind4_enc = Kind4MessageEncoder(
                update_obj.scanner_privkey_hex, update_obj.pubkey_to_query
            )
            enc_content = kind4_enc.encrypt_message(
                f"I corrected your relays on {update_obj.old_relays}"
            )
        except Exception as exc:
            enc_content = "a"
            print(f"enc cont error {exc}")
        try:
            await update_obj.send_event(
                update_obj.scanner_pubkey_hex,
                update_obj.scanner_privkey_hex,
                enc_content,
            )
        except Exception as exc:
            print(f"Exception is {exc}")
    except KeyboardInterrupt:
        print(f"keybord int")


asyncio.run(main())
