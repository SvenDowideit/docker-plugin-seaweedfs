# SeaweedFS Docker Plugin

This is stupendously experimental. I'm doing all sorts of not-recommended things to break out of Docker's attempts at confining plugins.


## Usage

Once running, you'll be able to use the `swarm` volume type just like you do local storage, but it will be accessible to any container, on any node.
multi-container access works, but there is no file-lock sharing, so you do need to deal with collisions in your code.

### Prerequisites

A Docker swarm.

### Installation

```
docker stack deploy -c seaweedfs.yml seaweedfs
```

This will start 
* a persistent volume server on every swarm node, 
* a non-persistent master node,
* an etcd node for persisting filer data on every master node
* an s3 container that talks to the filer (untested by me)
* the volume-plugin container on each node in the swarm.

To update the plugin on every node, you can run (you only need to do this once, it will go out to every node)

```
docker service update --force seaweedfs_docker-volume-plugin
```

## Mount options.

`mount.fuse` implements a number of options (see https://manpages.debian.org/testing/fuse/mount.fuse.8.en.html )

So far, this plugin supports only `uid`, `gid` and `umask`:

```
volumes:
  test:
    driver: swarm
    driver_opts:
      uid: 65534 #nobody - allow nginx running as nobody to read the files
      gid: 33 #www-data
      umask: 775
    name: "{{.Node.Hostname}}_{{.Service.Name}}"
```

## How it works.

The Plugin bindmounts in the host's Docker socket and `/var/lib/docker/plugins` dir. It uses this to work out what its called, and where it is supposed to mount files to. This allows the plugin to create intermediate containers that can access the seaweedfs_internal network to talk to the seaweedfs filer and volume services.

Right now, the `seaweedfs.yml` services compose file starts the seaweedfs services, and a "run-once" global service that installs this plugin on the other swarm nodes.

### Eventually

I want the plugin to start and update the seaweedfs swarm stack, and to listen to swarm events. This should allow it to dynamically change the
`defaultReplication` setting (presumably relative to the number of swarm masters), to send out the `re-balance` API signal, and keep things going.

I also want to see if I can make a Docker cli plugin that talks to the volume plugin to allow the user to use the docker cli to make seaweedfs config changes.



## `weed shell`

```
> volume.configure.replication -volumeId 1 -replication 001
> volume.configure.replication -volumeId 7 -replication 001
> volume.fix.replication
replicating volume 7 001 from 10.0.1.15:8080 to dataNode 10.0.1.14:8080 ...
replicating volume 1 001 from 10.0.1.15:8080 to dataNode 10.0.1.16:8080 ...
> volume.configure.replication -volumeId 7 -replication 002
> volume.configure.replication -volumeId 1 -replication 002
> volume.fix.replication
replicating volume 1 002 from 10.0.1.16:8080 to dataNode 10.0.1.14:8080 ...
replicating volume 7 002 from 10.0.1.14:8080 to dataNode 10.0.1.16:8080 ...
> 
```