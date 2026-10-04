"""Reusable MQTT connection and subscription client."""
from __future__ import annotations

import logging
import time
import base64
import secrets
import struct
from collections.abc import Callable
from datetime import datetime
from typing import Any

import paho.mqtt.client as mqtt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from meshtastic.protobuf import (
        admin_pb2,
        mesh_pb2,
        mqtt_pb2,
        paxcount_pb2,
        portnums_pb2,
        powermon_pb2,
        remote_hardware_pb2,
        storeforward_pb2,
        telemetry_pb2,
    )
except ImportError:
    from meshtastic import (
        admin_pb2,
        mesh_pb2,
        mqtt_pb2,
        paxcount_pb2,
        portnums_pb2,
        powermon_pb2,
        remote_hardware_pb2,
        storeforward_pb2,
        telemetry_pb2,
    )


class MeshtasticMqtt:
    """Own an MQTT connection and forward application callbacks."""

    def __init__(
        self,
        broker: str,
        port: int,
        username: str | None,
        password: str | None,
        topic: str,
        on_message: Callable[..., Any] | None = None,
        on_connected: Callable[[mqtt.Client], Any] | None = None,
    ) -> None:
        self.broker = broker
        self.port = port
        self.username = username
        self.password = password
        self.topic = topic
        self.on_connected = on_connected
        self.dup = {}
        self.channel_keys = {
            "LongFast": "1PG7OiApB1nwvP+rz05pAQ==",
            "LongSlow": "1PG7OiApB1nwvP+rz05pAQ==",
            "MediumFast": "1PG7OiApB1nwvP+rz05pAQ==",
            "MediumSlow": "1PG7OiApB1nwvP+rz05pAQ==",
            "ShortFast": "1PG7OiApB1nwvP+rz05pAQ==",
            "ShortSlow": "1PG7OiApB1nwvP+rz05pAQ==",
            "LongMod": "1PG7OiApB1nwvP+rz05pAQ==",
            "ShortTurbo": "1PG7OiApB1nwvP+rz05pAQ==",
        }
        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id="",
            clean_session=True,
            userdata=None,
        )
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        if on_message is not None:
            self.client.on_message = on_message

    def start(self) -> None:
        self.client.reconnect_delay_set(min_delay=1, max_delay=30)
        self._connect()
        self.client.loop_forever(retry_first_connection=True)

    def publish(self, topic: str, payload: bytes) -> mqtt.MQTTMessageInfo:
        return self.client.publish(topic, payload)

    @staticmethod
    def decode_service_envelope(payload: bytes):
        service_envelope = mqtt_pb2.ServiceEnvelope()
        service_envelope.ParseFromString(payload)
        return service_envelope, service_envelope.packet

    @staticmethod
    def encode_data(portnum: int, payload: bytes, want_response: bool = False):
        data = mesh_pb2.Data()
        data.portnum = portnum
        data.payload = payload
        data.want_response = want_response
        return data

    @staticmethod
    def decode_data(payload: bytes):
        data = mesh_pb2.Data()
        data.ParseFromString(payload)
        return data

    @staticmethod
    def portnum(name: str) -> int:
        return getattr(portnums_pb2, name)

    @staticmethod
    def portnum_name(packet) -> str:
        return portnums_pb2.PortNum.Name(packet.decoded.portnum)

    @staticmethod
    def is_portnum(packet, name: str) -> bool:
        return packet.decoded.portnum == MeshtasticMqtt.portnum(name)

    @staticmethod
    def encrypt_direct_message(
        private_key_a: bytes,
        public_key_b: bytes,
        plaintext: bytes,
        from_node: int,
        packet_id: int,
    ) -> bytes:
        if len(private_key_a) != 32 or len(public_key_b) != 32:
            raise ValueError("Curve25519 keys must be 32 bytes each.")

        extra_nonce_bytes = struct.pack("<I", secrets.randbits(32))
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_a)
        peer_key = x25519.X25519PublicKey.from_public_bytes(public_key_b)
        shared_secret = private_key.exchange(peer_key)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_secret)
        aes_key = digest.finalize()

        nonce = bytearray(b"\x00" * 16)
        nonce[0:8] = struct.pack("<Q", packet_id)
        nonce[8:12] = struct.pack("<I", from_node)
        nonce[4:8] = extra_nonce_bytes
        ciphertext_with_tag = AESCCM(aes_key, tag_length=8).encrypt(
            nonce[0:13], plaintext, None
        )
        return ciphertext_with_tag + extra_nonce_bytes

    @staticmethod
    def decrypt_direct_message(
        private_key_a: bytes,
        public_key_b: bytes,
        message: bytes,
        from_node: int,
        packet_id: int,
    ) -> bytes:
        if len(private_key_a) != 32 or len(public_key_b) != 32:
            raise ValueError("Curve25519 keys must be 32 bytes each.")
        if len(message) < 12:
            raise ValueError("Ciphertext must include the CCM tag and extra nonce.")

        ciphertext = message[:-12]
        tag = message[-12:-4]
        extra_nonce_bytes = message[-4:]
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_a)
        peer_key = x25519.X25519PublicKey.from_public_bytes(public_key_b)
        shared_secret = private_key.exchange(peer_key)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_secret)
        aes_key = digest.finalize()

        nonce = bytearray(b"\x00" * 16)
        nonce[0:8] = struct.pack("<Q", packet_id)
        nonce[8:12] = struct.pack("<I", from_node)
        nonce[4:8] = extra_nonce_bytes
        return AESCCM(aes_key, tag_length=8).decrypt(
            nonce[0:13], ciphertext + tag, None
        )

    @staticmethod
    def decode_payload(packet):
        payload_types = {
            portnums_pb2.NODEINFO_APP: mesh_pb2.User,
            portnums_pb2.POSITION_APP: mesh_pb2.Position,
            portnums_pb2.NEIGHBORINFO_APP: mesh_pb2.NeighborInfo,
            portnums_pb2.TELEMETRY_APP: telemetry_pb2.Telemetry,
            portnums_pb2.TRACEROUTE_APP: mesh_pb2.RouteDiscovery,
            portnums_pb2.ROUTING_APP: mesh_pb2.Routing,
            portnums_pb2.STORE_FORWARD_APP: storeforward_pb2.StoreAndForward,
            portnums_pb2.ADMIN_APP: admin_pb2.AdminMessage,
            portnums_pb2.REMOTE_HARDWARE_APP: remote_hardware_pb2.HardwareMessage,
            portnums_pb2.SIMULATOR_APP: mesh_pb2.Compressed,
            portnums_pb2.WAYPOINT_APP: mesh_pb2.Waypoint,
            portnums_pb2.PAXCOUNTER_APP: paxcount_pb2.Paxcount,
            portnums_pb2.MAP_REPORT_APP: mqtt_pb2.MapReport,
            portnums_pb2.POWERSTRESS_APP: powermon_pb2.PowerStressMessage,
        }
        payload_type = payload_types.get(packet.decoded.portnum)
        if payload_type is None:
            logging.info("*** Packet type not found: %s", packet.decoded.portnum)
            return None

        decoded_payload = payload_type()
        decoded_payload.ParseFromString(packet.decoded.payload)
        return decoded_payload

    @staticmethod
    def encode_service_envelope(packet, channel_id: str, gateway_id: str) -> bytes:
        service_envelope = mqtt_pb2.ServiceEnvelope()
        service_envelope.packet.CopyFrom(packet)
        service_envelope.channel_id = channel_id
        service_envelope.gateway_id = gateway_id
        return service_envelope.SerializeToString()

    def publish_mesh_packet(
        self,
        topic: str,
        channel_id: str,
        gateway_id: str,
        packet,
    ) -> mqtt.MQTTMessageInfo:
        payload = self.encode_service_envelope(packet, channel_id, gateway_id)
        return self.publish(topic, payload)

    @staticmethod
    def node_id_to_int(node_id: str) -> int:
        return int(node_id[1:], 16)

    @staticmethod
    def dec2hex(code: int) -> str:
        return "!" + hex(code)[2:].zfill(8)

    @staticmethod
    def base642hex(code: str) -> str:
        return hex(int.from_bytes(base64.b64decode(code), "big"))[2:].zfill(12)

    @staticmethod
    def hex2base64(code: str) -> str:
        value = int(code, 16)
        length = max(6, (value.bit_length() + 7) // 8)
        return base64.b64encode(value.to_bytes(length, "big")).decode("utf-8")

    def duplicated(self, key: int) -> bool:
        now = datetime.now()
        for duplicate_key in list(self.dup):
            if (now - self.dup[duplicate_key]).total_seconds() > 60:
                del self.dup[duplicate_key]

        if key in self.dup:
            return True

        self.dup[key] = now
        return False

    @staticmethod
    def _create_mesh_packet(message_id: int, source_id: str, destination_id: str):
        packet = mesh_pb2.MeshPacket()
        packet.id = message_id
        setattr(packet, "from", MeshtasticMqtt.node_id_to_int(source_id))
        packet.to = MeshtasticMqtt.node_id_to_int(destination_id)
        packet.want_ack = False
        packet.hop_limit = 3
        packet.hop_start = 3
        return packet

    @staticmethod
    def encode_encrypted_packet(
        message_id: int,
        source_id: str,
        destination_id: str,
        channel_id: str,
        data,
        key: str,
    ):
        packet = MeshtasticMqtt._create_mesh_packet(message_id, source_id, destination_id)
        packet.channel = MeshtasticMqtt._generate_hash(channel_id, key)
        key_bytes = base64.b64decode(key.encode("ascii"))
        nonce = packet.id.to_bytes(8, "little") + getattr(packet, "from").to_bytes(8, "little")
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        packet.encrypted = encryptor.update(data.SerializeToString()) + encryptor.finalize()
        return packet

    @staticmethod
    def encode_pki_packet(
        message_id: int,
        source_id: str,
        destination_id: str,
        data,
        private_key: str,
        public_key: str,
    ):
        packet = MeshtasticMqtt._create_mesh_packet(message_id, source_id, destination_id)
        packet.encrypted = MeshtasticMqtt.encrypt_direct_message(
            base64.b64decode(private_key),
            base64.b64decode(public_key),
            data.SerializeToString(),
            getattr(packet, "from"),
            message_id,
        )
        return packet

    @staticmethod
    def decode_encrypted_packet(packet, key: str):
        key_bytes = base64.b64decode(key.encode("ascii"))
        nonce = packet.id.to_bytes(8, "little") + getattr(packet, "from").to_bytes(8, "little")
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        return MeshtasticMqtt.decode_data(decryptor.update(packet.encrypted) + decryptor.finalize())

    def get_channel_keys(self) -> dict[str, str]:
        return self.channel_keys.copy()

    @staticmethod
    def decode_pki_packet(packet, private_key: str, public_key: str):
        decrypted = MeshtasticMqtt.decrypt_direct_message(
            base64.b64decode(private_key),
            base64.b64decode(public_key),
            packet.encrypted,
            getattr(packet, "from"),
            packet.id,
        )
        return MeshtasticMqtt.decode_data(decrypted)

    @staticmethod
    def _generate_hash(name: str, key: str) -> int:
        key_bytes = base64.b64decode(key.replace("-", "+").replace("_", "/").encode("utf-8"))
        return MeshtasticMqtt._xor_hash(name.encode("utf-8")) ^ MeshtasticMqtt._xor_hash(key_bytes)

    @staticmethod
    def _xor_hash(data: bytes) -> int:
        result = 0
        for value in data:
            result ^= value
        return result

    def disconnect(self) -> None:
        self.client.disconnect()

    def _connect(self) -> None:
        logging.info("connect_mqtt")
        while True:
            if self.username is not None:
                self.client.username_pw_set(self.username, self.password)
            logging.info("Connecting to MQTT broker at %s...", self.broker)
            try:
                self.client.connect(self.broker, self.port, 60)
                return
            except Exception as error:
                logging.warning("MQTT connection failed: %s", error)
                time.sleep(10)

    def _on_connect(
        self,
        client: mqtt.Client,
        userdata: Any,
        flags: dict[str, Any],
        reason_code: Any,
        properties: Any,
    ) -> None:
        if reason_code != 0:
            return
        client.subscribe(self.topic)
        logging.info("Connected to %s on topic %s", self.broker, self.topic)
        if self.on_connected is not None:
            self.on_connected(client)

    @staticmethod
    def _on_disconnect(
        client: mqtt.Client,
        userdata: Any,
        flags: Any,
        reason_code: Any,
        properties: Any,
    ) -> None:
        if reason_code != 0:
            logging.info("Disconnected from MQTT broker with result code %s", reason_code)
