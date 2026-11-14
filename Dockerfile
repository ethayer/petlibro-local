# Container build for Home Assistant Container. The add-on image remains addon/Dockerfile.
FROM python:3.13-alpine

RUN apk add --no-cache ffmpeg mosquitto \
    && pip3 install --no-cache-dir aiohttp==3.14.5 aiomqtt==2.5.1 tzdata==2026.5

COPY addon/app/ /app/
COPY addon/icon.png /app/icon.png

WORKDIR /app
ENV PYTHONUNBUFFERED=1
EXPOSE 8765
CMD ["python3", "/app/main.py"]
