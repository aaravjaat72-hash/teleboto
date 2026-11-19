FROM node:22-bookworm-slim

# Install ffmpeg, ffprobe, python3, curl, yt-dlp standalone, and SSL certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    ca-certificates \
    curl \
    python3 \
    && ARCH="$(uname -m)" \
    && if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then YTDLP_BIN="yt-dlp_linux_aarch64"; else YTDLP_BIN="yt-dlp_linux"; fi \
    && curl -fsSL -o /usr/local/bin/yt-dlp "https://github.com/yt-dlp/yt-dlp/releases/latest/download/${YTDLP_BIN}" \
    && chmod a+rx /usr/local/bin/yt-dlp \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package manifests first
COPY package*.json ./

# Install bot dependencies only
RUN npm install --include=dev --legacy-peer-deps

# Copy bot source files
COPY . .

ENV NODE_ENV=production \
    PORT=10000

# Ensure read/write permissions for bot state JSON files and temporary downloads
RUN chmod -R 777 /app

EXPOSE 10000

# Start standalone Telegram Bot + Keep-Alive Health Server
CMD ["npx", "tsx", "bot.ts"]
