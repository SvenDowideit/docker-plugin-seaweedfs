FROM golang:1.12-alpine as builder

WORKDIR /src
RUN set -ex \
    && apk add --no-cache --virtual .build-deps \
    gcc libc-dev git

ARG RELEASE_DATE
ENV RELEASE_DATE=$RELEASE_DATE
ARG COMMIT_HASH
ENV COMMIT_HASH=$COMMIT_HASH
ARG DIRTY
ENV DIRTY=$DIRTY

COPY go.* /src
RUN go mod download

COPY . /src
RUN set -ex \
    && echo --ldflags "-extldflags '-static' -X main.Version=${RELEASE_DATE} -X main.CommitHash=${COMMIT_HASH}${DIRTY}" \
    && go install --ldflags "-extldflags '-static' -X main.Version=${RELEASE_DATE} -X main.CommitHash=${COMMIT_HASH}${DIRTY}"

RUN set -ex \
    && apk del .build-deps
CMD ["/go/bin/docker-plugin-seaweedfs"]

FROM alpine
####
# Install SeaweedFS Client
####
ARG SEAWEEDFS_VERSION=1.42
ENV SEAWEEDFS_VERSION=$SEAWEEDFS_VERSION
RUN apk update && \
    apk add fuse && \
    apk add --no-cache --virtual build-dependencies --update wget curl ca-certificates && \
    wget -qO /tmp/linux_amd64.tar.gz https://github.com/chrislusf/seaweedfs/releases/download/${SEAWEEDFS_VERSION}/linux_amd64.tar.gz && \
    tar -C /usr/bin/ -xzvf /tmp/linux_amd64.tar.gz && \
    apk del build-dependencies && \
    rm -rf /tmp/*

# I have a docker socket, and this may help me test
RUN cd /tmp \
    && wget https://download.docker.com/linux/static/stable/x86_64/docker-19.03.0.tgz \
    && tar zxvf docker-19.03.0.tgz \
    && cp docker/docker /bin/ \
    && rm -rf docker*

# let non-root users fusemount
RUN echo "user_allow_other" >> /etc/fuse.conf

RUN mkdir -p /run/docker/plugins /mnt/state /mnt/volumes

COPY --from=builder /go/bin/docker-plugin-seaweedfs .
CMD ["/docker-plugin-seaweedfs"]
