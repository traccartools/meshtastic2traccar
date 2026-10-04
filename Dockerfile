FROM python:3.14-slim

COPY requirements.txt .
RUN pip install -r requirements.txt

WORKDIR /app
COPY app/ .

ENTRYPOINT [ "python", "meshtastic2traccar.py" ]
