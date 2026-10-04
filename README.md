# About

This little Docker container will connect to a Meshtastic MQTT server, decodes POSITION_APP packets and sends device locations to a [Traccar](https://www.traccar.org/) server.
In a multi-user environment it allows users to configure devices without involving the administrator.  
## How to

### Docker

Clone this repo and then add this to your `docker-compose.yml` file:

```yaml
  meshtastic2traccar:
    build: https://github.com/traccartools/meshtastic2traccar.git
    container_name: meshtastic2traccar  # optional
    environment:
      - MQTT_SERVER=mqtt.example.com
      - MQTT_PORT=1883
      - MQTT_USER=user
      - MQTT_PASSWORD=pass
      - MQTT_TOPIC=msh/#
      - TRACCAR_HOST=https://traccar.example.com  # optional, defaults to http://traccar:8082
      - TRACCAR_USER=user # optional but recommended
      - TRACCAR_PASSWORD=pass # optional but recommended
      - TRACCAR_KEYWORD=meshtastic_in # optional, defaults to meshtastic
      - TRACCAR_INTERVAL=120 # optional, defaults to 60
      - TRACCAR_OSMAND=http://traccar.example.com:5055  # optional, defaults to http://[TRACCAR_HOST]:5055
      - LOG_LEVEL=DEBUG  # optional, defaults to INFO
    restart: unless-stopped
  ```
  
  * `TRACCAR_HOST` is your Traccar server's URI/URL. If run in the same docker-compose stack, name your Traccar service `traccar` and omit this env var.
  * `TRACCAR_USER` is your Traccar server's username. It should be the admin or an admin user with readonly permission.
  * `TRACCAR_PASSWORD` is your Traccar server's password.
  * `TRACCAR_KEYWORD` is the attribute name to be set in your device.
  * `TRACCAR_INTERVAL` is the polling time (in seconds) of the traccar devices.
  * `TRACCAR_OSMAND` is your Traccar server's Osmand protocol URL. If omitted, it uses `http://[TRACCAR_HOST]:5055`.


### Traccar

Create a device with an arbitrary identifier.  
Add a device attribute with name = `TRACCAR_KEYWORD` and one of these values:

* Public packets: the Meshtastic node ID, for example `!12345678`.
* Private packets: four space-separated values: `!node_id node_public_key !server_id server_private_key`.

Wait `TRACCAR_INTERVAL` seconds in order for the changes takes effect.  

