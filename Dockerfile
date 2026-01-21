FROM python:3.11-slim

LABEL maintainer="r0zx"
LABEL description="MWAVS - Web Vulnerability Scanner"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

COPY . .
RUN pip install --no-cache-dir -e .

RUN useradd -m mwavs
USER mwavs

ENTRYPOINT ["python", "-m", "scanner.cli.main"]
CMD ["--help"]
EOF
