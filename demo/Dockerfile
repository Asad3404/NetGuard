# Image used by every node in the demo topology. It is just the NetGuard
# package on a slim Python base, plus tcpdump for eyeballing traffic.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/netguard
# Copy the whole repo build context (see docker-compose build context: ..).
COPY . /opt/netguard
RUN pip install --no-cache-dir -e .

# Keep containers alive; the demo script execs commands into them.
CMD ["sleep", "infinity"]
