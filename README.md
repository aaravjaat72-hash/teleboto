# Standalone Telegram Bot Only (Login + Scan + Download + 2GB Upload)

Is package mein **sirf Telegram Bot** ka complete code hai — koi frontend website, React, Vite ya admin UI nahi hai. Isko aap kisi bhi alag project, VPS, Docker, ya Render par seedha chala sakte ho.

## Included Features
- **Login & Auth**: Telegram Bot Token, 2GB MTProto Userbot (`TELEGRAM_STRING_SESSION`), `/weblogin` (cookie/token portal auth), `/setcookies`, `/addapi`, aur Admin/Developer role security.
- **Scan & Extract**: Course/Batch scan, webpage/JS/HLS `.m3u8` extractor, yt-dlp support, `/batches`, `/watch`, aur external portal mirror scanning.
- **Turbo Download**: Multi-threaded HLS segment downloader, AES-128 decrypt, FFmpeg fast MP4 remux, PDF notes download, queue/pause/resume/skip/only controls.
- **Turbo Upload**: Telegram Bot API (`<=50MB` HTTP/2) + 12/24-socket MTProto GramJS Userbot (`50MB - 2GB+`) auto routing, captions, thumbnails, aur live progress updates.
- **Main Admin Access Control**: `MAIN_ADMIN_ID` se owner account configure hota hai. Owner/Admin `/admin`, `/users`, `/approve`, `/revoke`, `/newcode`, `/invite`, `/addadmin` aur `/adddev` commands se user access aur rotating codes manage kar sakte hain.
- **24/7 Keep-Alive**: Minimal `/`, `/health`, `/api/ping` endpoints included so Render/Docker/UptimeRobot can keep the bot online 24/7.

## Quick Start (Local / VPS)
1. ZIP extract karein aur folder ke andar aayein.
2. `.env.example` ko copy karke `.env` banayein aur apna `TELEGRAM_BOT_TOKEN` (aur optional `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_STRING_SESSION`) daalein.
3. Dependencies install karke bot start karein:
   ```bash
   npm install
   npm start
   ```

## Deploy on Render / Docker
- Is folder ko apne naye GitHub repo mein push karein aur Render par **Web Service (Docker)** select karein (`Dockerfile` aur `render.yaml` ready hain).
- Render Environment Variables mein `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_STRING_SESSION`, aur apne Telegram numeric ID ke saath `MAIN_ADMIN_ID` set karein.
- Free 2-vCPU host par optional tuning: `TURBO_HLS_WORKERS=32`, `TURBO_RANGE_WORKERS=24`, `TURBO_UPLOAD_SOCKETS=8`. Ye bounded settings hain; actual speed source CDN, host bandwidth aur Telegram route par depend karegi.
- Health Check Path: `/api/ping`
