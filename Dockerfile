# The deployment image, built by .github/workflows/release.yml on every v* tag.
#
# ⭐ THE IMAGE IS BUILT FROM THE TAGGED CHECKOUT ITSELF. The operator's old recipe installed
# the package from `git+https://...@<tag>` inside the build, so the commit that was built was
# whatever the tag pointed at when the build ran. Here the workflow checks out the tag and
# installs THAT tree, and the provenance attestation names the same commit. One commit, one
# image, one signed statement that connects them.
#
# ⚠️ An older version of this file copied app.py and its siblings from the repository root.
# They moved into job_search_engine/ long ago, so it could not build at all. Nothing ran it.
#
# 📌 THE BASE IMAGE IS PINNED BY DIGEST (the multi-arch index of python:3.12-slim, read
# 2026-10-07). A tag alone moves, and the same tag rebuilt a week later is a different image.
# Bump the digest deliberately, in a commit that says why.
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

# git and ssh are for the /data working copy (gitsync.py). The volume is a cache of the
# private repo, which stays the source of truth, so the container has to be able to clone,
# pull and push.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Only what the package build reads. tests/, seed/ and .git stay out of the image.
# 📌 uvicorn comes with the package: pyproject.toml pins it exactly, with every other runtime
# dependency, so there is no second, unpinned install here.
# 📌 config/candidate.toml is deliberately NOT baked in: gitsync keeps a working copy at
# /data/repo, so changing a salary floor is a commit and a sync, not a rebuild.
COPY pyproject.toml README.md LICENSE /src/
COPY job_search_engine/ /src/job_search_engine/
RUN pip install --no-cache-dir /src && rm -rf /src

# Not needed when BUNNY_DATABASE_URL is set: storage is then the managed database.
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
CMD ["uvicorn","job_search_engine.app:app","--host","0.0.0.0","--port","8080"]
