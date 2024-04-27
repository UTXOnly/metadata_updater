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
            "b4869a297bfcd5a495814ee9c65f2bd0b267ca9bdbd08ce75dcd46281aa02bd8"
        )
        self.scanner_privkey_hex = (
            "ccfc6bdece62ba38ba9204ef63318d27b2b1d360dab1095bb65051337f3f6a47"
        )
        self.pubkey_to_query = ""
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
            print(len(items_list))
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

    def create_event(self, public_key, private_key_hex):
        tags = [["p", self.pubkey_to_query]]
        created_at = int(time.time())
        kind_number = 1
        content = f" I fixed your kind 0 metadata nostr:npub1g5pm4gf8hh7skp2rsnw9h2pvkr32sdnuhkcx9yte7qxmrg6v4txqqudjqv"  # {self.
        event_id = self.calc_event_id(
            public_key, created_at, kind_number, tags, content
        )
        signature_hex = self.sign_event_id(event_id, private_key_hex)
        event_data = {
            "id": event_id,  # event_id,
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

    async def send_event(self, public_key, private_key_hex):
        event_data = self.create_event(public_key, private_key_hex)
        print(f"event_created is: {event_data}")
        signature_valid = self.verify_signature(
            event_data.get("id"), public_key, event_data.get("sig")
        )
        if signature_valid:
            for ws_relay in self.relays_kind4:
                print(f"ws relay is {ws_relay}")
                try:
                    async with websockets.connect(ws_relay) as ws:
                        logger.info("WebSocket connection created.")

                        event_json = json.dumps(("EVENT", event_data))
                        await ws.send(event_json)
                        logger.info(f"Event sent: {event_json}")
                        response = json.loads(
                            await asyncio.wait_for(ws.recv(), timeout=1)
                        )
                        logger.info(f"DM response is {response}")
                        logger.info("WebSocket connection closed.")
                except Exception as exc:
                    logger.error(f"Failed to return DM to relay {ws_relay}")

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
                    query_dict["pubkey"] = self.pubkey_to_query
                    # query_dict["search"] = self.scanner_pubkey_hex

                query_ws = json.dumps(("REQ", "5326483051590112", query_dict))

                await ws.send(query_ws)
                logger.info(f"Query sent to relay {relay}: {query_ws}")
                try:
                    response = json.loads(await asyncio.wait_for(ws.recv(), timeout=1))

                    if response[0] == "EVENT":
                        if kinds == [4]:
                            print(f'dm sender is {response[2]["pubkey"]}')
                            self.return_event = response[2]["pubkey"]
                        return response[1]
                except asyncio.TimeoutError:
                    logger.info("No response within 1 second, continuing...")
        except Exception as exc:
            logger.error(f"Exception is {exc}")

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
            if note != None and note["pubkey"] == self.pubkey and note["kind"] == 0:
                try:
                    verified = self.verify_signature(
                        note["id"], note["pubkey"], note["sig"]
                    )
                    if verified:
                        self.good_relays.append(relay)
                        self.timestamp_set.add(note["created_at"])
                        self.calculate_latest_event(note)
                        self.all_good_relays[relay] = note["created_at"]
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
                response = json.loads(await asyncio.wait_for(ws.recv(), timeout=1))
                logger.debug(f"response 1 is {response[1]}")
                if response[1] == self.latest_note:
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
    start_time = time.time()

    update_obj = NoteUpdater()

    loop = asyncio.get_event_loop()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=200)
    loop.set_default_executor(executor)

    await update_obj.query_kind4()
    await update_obj.gather_queries()

    gather_time = time.time()
    print(f"--- {gather_time - start_time} seconds --- to query relays")

    update_obj.integrity_check_whole()
    logger.info(
        f"Relays that return the corect timestpamp are {update_obj.good_relays}, Relays with bad time stamps are: {update_obj.bad_relays}"
    )

    update_obj.calc_old_relays()
    calculate_time = time.time()
    print(f"--- {calculate_time - gather_time} seconds --- to perform calculations")

    await update_obj.gather_rebroadcast()
    rebroadcast_time = time.time()
    print(f"--- {rebroadcast_time - calculate_time} seconds --- to rebroadcast")

    final_time = time.time() - start_time
    print(f"--- {final_time} seconds --- final time")

    await update_obj.send_event(
        update_obj.scanner_pubkey_hex,
        update_obj.scanner_privkey_hex,
    )


asyncio.run(main())
