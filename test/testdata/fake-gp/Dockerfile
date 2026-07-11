FROM debian:trixie-slim@sha256:cedb1ef40439206b673ee8b33a46a03a0c9fa90bf3732f54704f99cb061d2c5a

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        python3-flask \
    && rm -rf /var/lib/apt/lists/*

COPY fake-gp-server.py /usr/local/bin/fake-gp-server.py

EXPOSE 443/tcp

ENTRYPOINT ["python3", "/usr/local/bin/fake-gp-server.py"]
