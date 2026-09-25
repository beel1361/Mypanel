#!/bin/sh
set -eu
mkdir -p /data/xray
python3 - <<'PY'
from app import init, reality_setup, build_config, ensure_nginx
init(); reality_setup(); build_config(); ensure_nginx()
PY
# The web app is internal; nginx owns Railway's HTTP port.
uvicorn app:app --host 127.0.0.1 --port 8081 >/data/panel.log 2>&1 &
sleep 2
nginx -t
nginx -g 'daemon off;' >/data/nginx.log 2>&1 &
sleep 2
exec /usr/local/bin/xray run -config /data/xray/config.json
