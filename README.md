# Meshtastic to Traccar

Docker service that reads Meshtastic `POSITION_APP` packets from MQTT and
sends matching positions to [Traccar](https://www.traccar.org/) through the
OsmAnd protocol.

## Docker Compose

```yaml
  meshtastic2traccar:
    build: https://github.com/traccartools/meshtastic2traccar.git
    environment:
      MQTT_SERVER: mqtt.example.com
      MQTT_PORT: "1883"
      MQTT_USER: user
      MQTT_PASSWORD: pass
      MQTT_TOPIC: msh/#
      TRACCAR_HOST: http://traccar:8082
      TRACCAR_USER: user
      TRACCAR_PASSWORD: pass
      TRACCAR_OSMAND: http://traccar:5055
      TRACCAR_KEYWORD: meshtastic
      TRACCAR_INTERVAL: "60"
      LOG_LEVEL: INFO
    restart: unless-stopped
```

  ### Docker options

  | Option | Description |
  | --- | --- |
  | `MQTT_SERVER` | MQTT broker hostname. |
  | `MQTT_PORT` | MQTT broker port. |
  | `MQTT_USER` / `MQTT_PASSWORD` | MQTT credentials. |
  | `MQTT_TOPIC` | MQTT topic to subscribe to. |
  | `TRACCAR_HOST` | Traccar API URL. |
  | `TRACCAR_USER` / `TRACCAR_PASSWORD` | Traccar API credentials used to read devices and attributes. |
  | `TRACCAR_OSMAND` | Traccar OsmAnd endpoint, normally port `5055`. |
  | `TRACCAR_KEYWORD` | Prefix used for Traccar mapping attributes. Default: `meshtastic`. |
  | `TRACCAR_INTERVAL` | Seconds between Traccar device polls. Default: `60`. |
  | `LOG_LEVEL` | Logging level, for example `INFO` or `DEBUG`. |

  `TRACCAR_KEYWORD` defines the attribute name used for the mapping. For
  example, with `TRACCAR_KEYWORD=meshtastic`, use attributes named
  `meshtastic`, `meshtastic1`, `meshtastic2`, and so on. The value of each
  attribute is the public or private mapping described below.

## Traccar mapping

Create a Traccar device and add an attribute named `meshtastic` (or
`meshtastic1`, `meshtastic2`, etc.). The attribute value selects the position
type.

### Public position

Use the Meshtastic node ID:

```text
!12345678
```

The packet sender is matched to this ID and decrypted with the channel key.

### Private position

Meshtastic normally broadcasts position packets publicly. Private position
packets require a custom Meshtastic firmware that sends the position through
the encrypted PKI channel; this is not enabled by the standard firmware.

Use four space-separated fields:

```text
!node_id node_public_key !server_id server_private_key
```

Example:

```text
!12345678 OvK2BQpCotPQdl38F8ICT3wOVbZISyu+thNZn1NJ3xI= !87654321 QGWR4kGqel2piIgQqVNncTErRwrdozQtcuKZ6/HhBlI=
```

The application matches both sender and destination, then decrypts the packet
with the node public key and server private key. Keys must be base64-encoded
32-byte Curve25519 keys.

`node_id` and `server_id` must contain eight hexadecimal digits prefixed by
`!`. Changes are applied after the next `TRACCAR_INTERVAL` poll.

