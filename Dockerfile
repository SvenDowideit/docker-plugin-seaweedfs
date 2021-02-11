# https://hub.docker.com/_/golang?tab=tags&page=1&ordering=last_updated
FROM golang:1.15-alpine as builder

WORKDIR /src
RUN set -ex \
    && apk add --no-cache --virtual .build-deps \
    gcc libc-dev git

ARG RELEASE_DATE
ENV RELEASE_DATE=$RELEASE_DATE
ARG PLUGIN_TAG
ENV PLUGIN_TAG=$PLUGIN_TAG
ARG COMMIT_HASH
ENV COMMIT_HASH=$COMMIT_HASH
ARG DIRTY
ENV DIRTY=$DIRTY

COPY go.* /src/
RUN go mod download

COPY . /src/
RUN set -ex \
    && echo --ldflags "-extldflags '-static' -X main.Version=${RELEASE_DATE} -X main.BranchName=${PLUGIN_TAG} -X main.CommitHash=${COMMIT_HASH}${DIRTY}" \
    && go install --ldflags "-extldflags '-static' -X main.Version=${RELEASE_DATE} -X main.BranchName=${PLUGIN_TAG} -X main.CommitHash=${COMMIT_HASH}${DIRTY}"

RUN set -ex \
    && apk del .build-deps
CMD ["/go/bin/docker-plugin-seaweedfs"]

FROM alpine
####
# Install SeaweedFS Client
####
ARG SEAWEEDFS_VERSION=2.24
ENV SEAWEEDFS_VERSION=$SEAWEEDFS_VERSION
RUN apk update && \
    apk add fuse curl && \
    apk add --no-cache --virtual build-dependencies --update wget ca-certificates && \
    echo "DOWNLOAD seaweedfs ${SEAWEEDFS_VERSION}" && \
    wget -qO /tmp/linux_amd64.tar.gz https://github.com/chrislusf/seaweedfs/releases/download/${SEAWEEDFS_VERSION}/linux_amd64.tar.gz && \
    echo "got seaweedfs ${SEAWEEDFS_VERSION}" && \
    tar -C /usr/bin/ -xzvf /tmp/linux_amd64.tar.gz && \
    apk del build-dependencies && \
    rm -rf /tmp/*

# I have a docker socket, and this may help me test
ARG DOCKER_VERSION=19.03.15
ENV DOCKER_VERSION=$DOCKER_VERSION
RUN cd /tmp \
    && wget https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz \
    && tar zxvf docker-${DOCKER_VERSION}.tgz \
    && cp docker/docker /bin/ \
    && rm -rf docker*

# let non-root users fusemount
RUN echo "user_allow_other" >> /etc/fuse.conf

RUN mkdir -p /run/docker/plugins /mnt/state /mnt/volumes

COPY --from=builder /go/bin/docker-plugin-seaweedfs .
CMD ["/docker-plugin-seaweedfs"]
