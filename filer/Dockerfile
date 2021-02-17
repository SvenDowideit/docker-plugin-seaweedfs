FROM chrislusf/seaweedfs:latest

RUN apk add --no-cache bind-tools

COPY filer.sh /filer.sh
COPY filer.toml /etc/seaweedfs/filer.toml

ENTRYPOINT /filer.sh
