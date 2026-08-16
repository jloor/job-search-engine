FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

# git and ssh are for the /data working copy (gitsync.py). The volume is a cache of the
# private repo, which stays the source of truth, so the container has to be able to clone,
# pull and push.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git openssh-client \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ⚠️ candidate.py and gates.py hold the rules that decide which jobs are shown. They ran
# as CLI tools during a backfill while the deployed service applied an older, looser set,
# so the nightly sweep and the manual run disagreed. They ship together now.
# 📌 config/candidate.toml is deliberately NOT baked in: gitsync keeps a working copy at
# /data/repo, so changing a salary floor is a commit and a sync, not a rebuild. Before the
# first clone lands there is no config, and the scan job declines rather than running with
# no filters at all.
COPY schema.sql app.py gitsync.py backup.py candidate.py gates.py ./

# persistent volume mounts here (Bunny Magic Containers: attach a volume at /data)
# Not needed when BUNNY_DB_URL is set: storage is then the managed database.
ENV DB_PATH=/data/relay.db
VOLUME ["/data"]

# Nothing in this service needs root. The SMTP credential lives in this process,
# so a bug that gets code execution should not also get the machine.
RUN useradd --system --uid 10001 --home /app relay \
 && mkdir -p /data && chown -R relay:relay /app /data
USER relay

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health').read()" || exit 1

# NO --proxy-headers on purpose. With it, uvicorn rewrites request.client.host from
# X-Forwarded-For, and if --forwarded-allow-ips is ever widened to '*' it takes the
# LEFT-most entry, which the caller controls. client_ip() in app.py counts in from the
# right by a known hop count instead. One component owns this decision, explicitly.
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8080"]
