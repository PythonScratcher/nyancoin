FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NYAN_HOME=/data/home

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
 && useradd --system --uid 10001 --home-dir /data nyan \
 && mkdir -p /data && chown nyan:nyan /data && chmod 700 /data

COPY node.py miner.py wallet.py README.md /app/
COPY deploy/docker-entrypoint.sh /usr/local/bin/nyancoin
# --version also runs each file's rules-lock check, so a modified file fails the build
RUN chmod 755 /usr/local/bin/nyancoin \
 && python /app/node.py --version && python /app/miner.py --version && python /app/wallet.py --version

USER nyan
WORKDIR /data
VOLUME /data
EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD python /app/wallet.py status --node "https://127.0.0.1:${PORT:-8001}" > /dev/null || exit 1

ENTRYPOINT ["nyancoin"]
CMD ["node"]
