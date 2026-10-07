#!/usr/bin/env python3

import logging
import os
import signal

from geopy.distance import geodesic
import requests

from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from urllib.parse import urlparse, urlunparse
from requests.auth import HTTPBasicAuth
import json
import re

from meshtastic_mqtt import MeshtasticMqtt

DEFAULT_TRACCAR_HOST = 'http://traccar:8082'
DEFAULT_TRACCAR_KEYWORD = 'meshtastic'
DEFAULT_TRACCAR_INTERVAL = 60

logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger('apscheduler').setLevel(logging.WARNING)


class Meshtastic2Traccar():
    def __init__(self, conf: dict):
        super().__init__()

        self.TraccarHost = conf.get("TraccarHost")
        self.TraccarUser = conf.get("TraccarUser")
        self.TraccarPassword = conf.get("TraccarPassword")
        self.TraccarKeyword = conf.get("TraccarKeyword")
        self.TraccarOsmand = conf.get("TraccarOsmand")
        self.filter_dict = {}
        self.mqtt_broker = conf.get("MqttServer") or "mqtt.meshtastic.org"
        self.mqtt_port = int(conf.get("MqttPort") or "1883")
        self.mqtt_username = conf.get("MqttUser") or "meshdev"
        self.mqtt_password = conf.get("MqttPassword") or "large4cats"
        self.subscribe_topic = conf.get("MqttTopic") or "msh/EU_868/#"
        self.MeshtasticMqtt = MeshtasticMqtt(
            self.mqtt_broker,
            self.mqtt_port,
            self.mqtt_username,
            self.mqtt_password,
            self.subscribe_topic,
            on_message=self.on_message,
        )
        self.channel_keys = self.MeshtasticMqtt.get_channel_keys()

    @staticmethod
    def position_accuracy(latitude: float, longitude: float, precision_bits: int) -> int:
        """Return the maximum geodesic distance from the cell center to a corner."""
        if precision_bits >= 32:
            return 0

        half_cell_degrees = 2 ** (31 - max(precision_bits, 10)) * 1e-7
        corners = [
            (latitude + half_cell_degrees, longitude + half_cell_degrees),
            (latitude - half_cell_degrees, longitude - half_cell_degrees),
        ]

        return round(max(geodesic((latitude, longitude), corner).meters for corner in corners))

    def start(self):
        self.MeshtasticMqtt.start()

    def on_message(self, client, userdata, msg):
        if not re.match("^msh/(.*/)*2/e", msg.topic):
            return()

        try:
            se, mp = self.MeshtasticMqtt.decode_service_envelope(msg.payload)
        except Exception as e:
            logging.debug(f"*** ServiceEnvelope: {str(e)}")
            return

        if not (getattr(mp, "from") and getattr(mp, "to") and getattr(mp, "id")):
            logging.debug(f"*** NO from, to or id: {mp}")
            return
        
        i_topic = msg.topic
        i_short_topic = "/".join(msg.topic.split("/")[:-4])
        i_id = getattr(mp, "id")
        i_from = self.MeshtasticMqtt.dec2hex(getattr(mp, "from"))
        i_to = self.MeshtasticMqtt.dec2hex(getattr(mp, "to"))
        i_chan = se.channel_id # This can be obtained from the topic.
        i_gateway = se.gateway_id # This can be obtained from the topic.
        i_hopstart = getattr(mp, "hop_start")
        i_hoplimit = getattr(mp, "hop_limit")
        i_hops = i_hopstart - i_hoplimit


        node_filter = self.filter_dict.get(i_from)
        if not node_filter:
            return()

        is_private = re.match("^msh/(.*/)*2/e/PKI", msg.topic) is not None
        dev_ids = None

        if is_private:
            # Filter private packets by sender and destination.
            server_pairs = node_filter["private"].get(i_to, {})
            if not server_pairs:
                return()
        else:
            # Filter public packets by sender.
            dev_ids = node_filter["public"]
            if not dev_ids:
                return()

        # Find duplicates.
        isdup = self.MeshtasticMqtt.duplicated(getattr(mp, "id"))
        if isdup:
            return()


        if mp.HasField("encrypted") and not mp.HasField("decoded"):
            if is_private:
                decoded = None
                dev_ids = None
                for key_pair, candidate_device_ids in server_pairs.items():
                    node_public_key, server_private_key = key_pair.split(":", 1)
                    try:
                        decoded = self.MeshtasticMqtt.decode_pki_packet(
                            mp,
                            server_private_key,
                            node_public_key,
                        )
                        dev_ids = candidate_device_ids
                        break
                    except Exception:
                        continue

                if decoded is None:
                    logging.warning("Unable to decrypt packet from %s", i_from)
                    return()
                mp.decoded.CopyFrom(decoded)
            else:
                channel_key = self.channel_keys.get(i_chan)
                if channel_key is None:
                    logging.debug("No channel key configured for %s", i_chan)
                    return()
                try:
                    mp.decoded.CopyFrom(
                        self.MeshtasticMqtt.decode_encrypted_packet(mp, channel_key)
                    )
                except Exception as error:
                    logging.warning("Unable to decrypt public packet from %s: %s", i_from, error)
                    return()

        if is_private and dev_ids is None:
            dev_ids = next(iter(server_pairs.values()))

        # Get the port number.
        i_protocol = self.MeshtasticMqtt.portnum_name(mp)
                
        if not mp.HasField("decoded"):
            return()
        
        if not self.MeshtasticMqtt.is_portnum(mp, "POSITION_APP"):
            return()
        
        pl = None
        try:
            pl = self.MeshtasticMqtt.decode_payload(mp)
        except Exception as e:
            logging.debug(f"*** packet decode failed: {str(e)}")
            return()




        # print ("")
        # print ("Service Envelope:")
        # print (se)
        # print ("")
        # print ("Message Packet:")
        # print (mp)
       
        
        # Fully decoded packet.
        
        logging.info(", ".join(map(str,[i_from, i_to, i_chan, i_gateway, i_id, i_short_topic, i_protocol])))

        lat = round(pl.latitude_i * 1e-7, 5)
        lon = round(pl.longitude_i * 1e-7, 5)
        alt = pl.altitude
        
        name = self.MeshtasticMqtt.dec2hex(getattr(mp, "from"))
        # print(pl.precision_bits)
        # Previous approximation: latitude semi-cell size at precision 10.
        # accuracy = int(23300 / 2 ** (max(pl.precision_bits, 10) - 10))
        accuracy = self.position_accuracy(lat, lon, pl.precision_bits)

        speed = pl.ground_speed
        course = 0
        fixTime =  pl.time

        for dev_id in dev_ids:
            query_string = f"id={dev_id}&lat={lat}&lon={lon}&alt={alt}&accuracy={accuracy}&speed={speed}&bearing={course}" \
            f"&meshtastic_chan={i_chan}&meshtastic_topic={i_short_topic}&meshtastic_gateway={i_gateway}&meshtastic_hops={i_hops}"

            try:
                self.tx_to_traccar(query_string)
            except ValueError:
                logging.warning(f"id={dev_id}")




    def tx_to_traccar(self, query: str):
        # Send position report to Traccar server
        logging.debug(f"tx_to_traccar({query})")
        url = f"{self.TraccarOsmand}/?{query}"
        try:
            post = requests.post(url)
            logging.debug(f"POST {post.status_code} {post.reason} - {post.content.decode()}")
            if post.status_code == 400:
                logging.warning(
                    f"{post.status_code}: {post.reason}. Please create device with matching identifier on Traccar server.")
                raise ValueError(400)
            elif post.status_code > 299:
                logging.error(f"{post.status_code} {post.reason} - {post.content.decode()}")
        except OSError:
            logging.exception(f"Error sending to {url}")





    def poll(self):
        page = requests.get(self.TraccarHost + "/api/devices?all=true", auth = HTTPBasicAuth(self.TraccarUser, self.TraccarPassword))
        if page.status_code != 200:
            logging.info("Traccar auth failed")
            return

        filterdict = {}
        logging.debug("*** Searching for devices ***")
        for j in json.loads(page.content):
            # print(self.TraccarKeyword)
            # print(json.dumps(j, indent=2))
            
            if not j["disabled"]:
                attributes = j["attributes"]
                

                for att, value in attributes.items():
                    if re.search("^" + self.TraccarKeyword + "[0-9]{0,1}$", att.lower()):
                        value = value.strip()
                        fields = value.split()
                        if len(fields) == 1 and re.fullmatch(r"![0-9A-Fa-f]{8}", fields[0]):
                            node_filter = filterdict.setdefault(
                                fields[0].lower(),
                                {"private": {}, "public": []},
                            )
                            node_filter["public"].append(j["uniqueId"])
                            continue

                        if len(fields) != 4:
                            logging.warning(
                                "Invalid Meshtastic mapping for uniqueId %s",
                                j["uniqueId"],
                            )
                            continue

                        node_id, node_public_key, server_id, server_private_key = fields
                        if not re.fullmatch(r"![0-9A-Fa-f]{8}", node_id):
                            continue
                        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", node_public_key):
                            continue
                        if not re.fullmatch(r"![0-9A-Fa-f]{8}", server_id):
                            continue
                        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", server_private_key):
                            continue

                        node_id = node_id.lower()
                        server_id = server_id.lower()
                        key_pair = f"{node_public_key}:{server_private_key}"
                        node_filter = filterdict.setdefault(
                            node_id,
                            {"private": {}, "public": []},
                        )
                        server_pairs = node_filter["private"].setdefault(server_id, {})
                        server_pairs.setdefault(key_pair, []).append(j["uniqueId"])


        for node_id, node_filter in filterdict.items():
            for unique_id in node_filter["public"]:
                logging.debug(
                    "node=%s uniqueId=%s",
                    node_id,
                    unique_id,
                )
            for server_id, key_configs in node_filter["private"].items():
                for device_ids in key_configs.values():
                    for unique_id in device_ids:
                        logging.debug(
                            "node=%s server=%s uniqueId=%s",
                            node_id,
                            server_id,
                            unique_id,
                        )
        self.filter_dict = filterdict























if __name__ == '__main__':
    
    log_level = os.environ.get("LOG_LEVEL", "DEBUG")
    logging.basicConfig(format="%(asctime)s: %(message)s", level=log_level, datefmt="%H:%M:%S")


    def sig_handler(sig_num, frame):
        logging.debug(f"Caught signal {sig_num}: {frame}")
        logging.info("Exiting program.")
        exit(0)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    def OsmandURL(url):
        u = urlparse(url)
        u = u._replace(scheme="http", netloc=u.hostname+":5055", path = "")
        return(urlunparse(u))

    config = {}
    config["TraccarHost"] = os.environ.get("TRACCAR_HOST", DEFAULT_TRACCAR_HOST)
    config["TraccarUser"] = os.environ.get("TRACCAR_USER", "")
    config["TraccarPassword"] = os.environ.get("TRACCAR_PASSWORD", "")
    config["TraccarKeyword"] = os.environ.get("TRACCAR_KEYWORD", DEFAULT_TRACCAR_KEYWORD)
    config["TraccarInterval"] = int(os.environ.get("TRACCAR_INTERVAL", DEFAULT_TRACCAR_INTERVAL))
    config["TraccarOsmand"] = os.environ.get("TRACCAR_OSMAND", OsmandURL(config["TraccarHost"]))

    config["MqttServer"] = os.environ.get("MQTT_SERVER")
    config["MqttPort"] = os.environ.get("MQTT_PORT")
    config["MqttUser"] = os.environ.get("MQTT_USER")
    config["MqttPassword"] = os.environ.get("MQTT_PASSWORD")
    config["MqttTopic"] = os.environ.get("MQTT_TOPIC")


    M2T = Meshtastic2Traccar(config)

    scheduler = BackgroundScheduler()
    scheduler.add_job(M2T.poll, 'interval', next_run_time=datetime.now(), seconds=config["TraccarInterval"])
    scheduler.start()

    M2T.start()

