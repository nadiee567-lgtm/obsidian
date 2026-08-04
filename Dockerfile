# OBSIDIAN — imagen reproducible (F7 paso 100)
FROM python:3.14-slim

# Herramientas de sistema que enriquecen algunos transforms (todas opcionales:
# el motor degrada si faltan). nuclei/playwright quedan fuera a propósito para
# mantener la imagen ligera — se añaden aparte si se necesitan.
RUN apt-get update && apt-get install -y --no-install-recommends \
        dnsutils whois exiftool nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Deps de Python primero (mejor caché de capas)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Datos persistentes (workspaces + bóveda) fuera del contenedor
VOLUME ["/root/.obsidian"]
EXPOSE 8767

# Bind a toda interfaz DENTRO del contenedor; expón el puerto con cuidado
ENV OBSIDIAN_HOST=0.0.0.0
# OBSIDIAN_PASSWORD debe pasarse en runtime (-e OBSIDIAN_PASSWORD=...)
CMD ["python", "obsidian_web.py"]
