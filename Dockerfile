# OBSIDIAN -- reproducible image (F7 step 100)
FROM python:3.14-slim

# System tools that enrich some transforms (all optional: the engine degrades if
# missing). nuclei/playwright are left out on purpose to keep the image light --
# add them separately if needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
        dnsutils whois exiftool nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Persistent data (workspaces + vault) outside the container
VOLUME ["/root/.obsidian"]
EXPOSE 8767

# Bind to every interface INSIDE the container; expose the port carefully
ENV OBSIDIAN_HOST=0.0.0.0
# OBSIDIAN_PASSWORD must be passed at runtime (-e OBSIDIAN_PASSWORD=...)
CMD ["python", "obsidian_web.py"]
