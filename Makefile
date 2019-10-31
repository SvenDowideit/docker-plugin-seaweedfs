.PHONY: all build clean rootfs create enable ps enter test mountall logs push

PREFIX = svendowideit/seaweedfs-volume
PLUGIN_NAME = ${PREFIX}-plugin
PLUGIN_TAG ?=$(shell git rev-parse --abbrev-ref HEAD)

RELEASE_DATE=$(shell date +%F)
COMMIT_HASH=$(shell git rev-parse --short HEAD 2>/dev/null)
GITSTATUS=$(shell git status --porcelain --untracked-files=no)
ifneq ($(GITSTATUS),)
  DIRTY=-dirty
endif

all: clean push-rootfs

build:
	go build --ldflags "-extldflags '-static' \
		-X main.Version=${RELEASE_DATE} \
		-X main.BranchName=${PLUGIN_TAG} \
		-X main.CommitHash=${COMMIT_HASH}${DIRTY}" \
		.

clean:
	@echo "### rm ./plugin"
	@rm -rf ./plugin

rootfs:
	@echo "### docker build: rootfs image with ${PLUGIN_NAME}-rootfs:${PLUGIN_TAG} (${RELEASE_DATE}) ${COMMIT_HASH}${DIRTY}"
	@echo "${GITSTATUS}"
	@docker build --target builder -t ${PLUGIN_NAME}-rootfs:build-${PLUGIN_TAG} \
		--build-arg "RELEASE_DATE=${RELEASE_DATE}" \
		--build-arg "PLUGIN_TAG=${PLUGIN_TAG}" \
		--build-arg "COMMIT_HASH=${COMMIT_HASH}" \
		--build-arg "DIRTY=${DIRTY}" .
	@docker build -t ${PLUGIN_NAME}-rootfs:${PLUGIN_TAG} \
		--build-arg "RELEASE_DATE=${RELEASE_DATE}" \
		--build-arg "PLUGIN_TAG=${PLUGIN_TAG}" \
		--build-arg "COMMIT_HASH=${COMMIT_HASH}" \
		--build-arg "DIRTY=${DIRTY}" .
	@echo "### create rootfs directory in ./plugin/rootfs"
	@mkdir -p ./plugin/rootfs
	@docker create --name tmp ${PLUGIN_NAME}-rootfs:${PLUGIN_TAG}
	@docker export tmp | tar -x -C ./plugin/rootfs
	@echo "### add version into to config.json and stage into ./plugin/"
	@RELEASE_DATE=${RELEASE_DATE} COMMIT_HASH=${COMMIT_HASH} DIRTY=${DIRTY} envsubst > ./plugin/config.json < config.json
	@docker rm -vf tmp

push-rootfs: rootfs
	@echo "### push rootfs ${PLUGIN_NAME}:${PLUGIN_TAG}"
	@docker push ${PLUGIN_NAME}-rootfs:build-${PLUGIN_TAG}
	@docker push ${PLUGIN_NAME}-rootfs:${PLUGIN_TAG}

run-rootfs:
	@docker run --rm -it \
		-v /var/lib/docker/plugins/seaweedfs/rootfs/tmp:/tmp \
		-v /var/lib/docker/plugins/seaweedfs/rootfs/mnt:/mnt \
		-v /var/lib/docker/plugins/seaweedfs/propagated-mount:/propagated-mount \
		-v /run:/run \
		--net=seaweedfs_internal \
		-e DEBUG=true \
		${PLUGIN_NAME}-rootfs:${PLUGIN_TAG}

# not using real managed docker plugins now, using a swarm service
# create:
# 	@echo "### remove existing plugin swarm if exists"
# 	@docker volume rm -f test4 || true
# 	@docker plugin rm -f ${PLUGIN_NAME}:${PLUGIN_TAG} || true
# 	@echo "### create new plugin for pushing to Docker hub ${PLUGIN_NAME}:${PLUGIN_TAG} from ./plugin"
# 	@docker plugin create ${PLUGIN_NAME}:${PLUGIN_TAG} ./plugin
# 	@docker plugin set ${PLUGIN_NAME}:${PLUGIN_TAG} DEBUG=true

# #TODO: add an "ensure seaweedfs stack is up and running step that is used by "make all"

# enable:		
# 	@echo "### enable plugin ${PLUGIN_NAME}:${PLUGIN_TAG}"
# 	@docker plugin enable ${PLUGIN_NAME}:${PLUGIN_TAG}

# ps:
# 	@ps -U root -u | grep docker-plugin-seaweedf

# enter:
# 	@sudo nsenter --target $(shell ps -U root -u | grep /docker-plugin-seaweedfs | xargs | cut -f2 -d" ") --mount --uts --ipc --net --pid sh

mk-test-mount:
	@docker volume create -d ${PLUGIN_NAME}:${PLUGIN_TAG} -o uid=33 -o gid=10 -o umask=0773 test4

test:
	@docker kill tester | true
	@docker volume rm -f test4 | true
	@sleep 1

	@docker volume create -d ${PLUGIN_NAME}:${PLUGIN_TAG} -o uid=33 -o gid=10 -o umask=0773 test4
	@docker run -d --name tester -u 33  --rm -it -v test4:/test debian sh

	@docker run --rm -it -v test4:/test debian ls -al | grep test
	@docker run --rm -it -v test4:/test debian ls -al /test/
	@docker run --rm -it -v test4:/test debian bash -c "mktemp -p /test/ -t tmp.root.XXXXX"
	@docker run --rm -it -u 33 -v test4:/test debian bash -c 'chmod 600 $$(mktemp -p /test/ -t tmp.uid33.XXXXX)'

	@docker run --rm -it -v test4:/test debian ls -al /test/

	@echo "is the volume plugin mount container running:"
	@docker ps | grep seaweed-volume | grep test4

	@docker kill tester

	@echo "is the volume plugin mount container gone:"
	@docker ps -a | grep seaweed-volume-proxy | grep test4 | true

	@docker volume rm -f test4 | true

# TODO: need a test-clean that removes the dirs from seaweedfs
# TODO: and some way to "start over" (atm, remove the seaweedfs stack, remove the volumes)


mountall:
	@docker run --rm -it --net=seaweedfs_internal --cap-add=SYS_ADMIN --device=/dev/fuse:/dev/fuse --security-opt=apparmor:unconfined --entrypoint=weed ${PLUGIN_NAME}:${PLUGIN_TAG} mount -filer=filer:8888 -dir=/mnt -filer.path=/


# logs:
# 	@sudo journalctl -fu docker | grep $(shell docker plugin inspect --format "{{.Id}}" ${PLUGIN_NAME}:${PLUGIN_TAG})

# push:  clean rootfs create enable
# 	@echo "### push plugin ${PLUGIN_NAME}:${PLUGIN_TAG}"
# 	@docker push ${PLUGIN_NAME}-rootfs:build-${PLUGIN_TAG}
# 	@docker push ${PLUGIN_NAME}-rootfs:${PLUGIN_TAG}
# 	@docker plugin push ${PLUGIN_NAME}:${PLUGIN_TAG}
