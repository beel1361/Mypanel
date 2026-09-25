FROM debian:bookworm-slim
ARG XRAY_VERSION=26.5.9
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 DATA_DIR=/data PORT=8080
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip nginx ca-certificates curl unzip procps iproute2 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip && unzip -q /tmp/xray.zip xray -d /usr/local/bin && chmod +x /usr/local/bin/xray && rm -f /tmp/xray.zip
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt
COPY app.py .
COPY templates templates
COPY static static
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh && rm -f /etc/nginx/sites-enabled/default
EXPOSE 8080
CMD ["/app/entrypoint.sh"]
