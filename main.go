package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	//"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-plugins-helpers/volume"
	"github.com/sirupsen/logrus"

	etcd "github.com/abronan/valkeyrie/store/etcd/v2"
)

// mostly swiped from https://github.com/vieux/docker-volume-sshfs/blob/master/main.go

const socketAddress = "/run/docker/plugins/swarm.sock"

// Version is set from the go build commandline
var Version string

// CommitHash is set from the go build commandline
var CommitHash string

// BranchName is set from the go build commandline
var BranchName string

// plugin image name
var imageName string

type seaweedfsDriver struct {
	root string
}

func newseaweedfsDriver(root string) (*seaweedfsDriver, error) {
	logrus.WithField("method", "new driver").Debug(root)

	etcd.Register()

	d := &seaweedfsDriver{
		root: filepath.Join(root, "volumes"),
	}

	return d, nil
}

// Create Instructs the plugin that the user wants to create a volume,
// given a user specified volume name. The plugin does not need to actually
// manifest the volume on the filesystem yet (until Mount is called).
// Opts is a map of driver specific options passed through from the user request.
func (d *seaweedfsDriver) Create(r *volume.CreateRequest) error {
	logrus.WithField("method", "create").Debugf("%#v", r)

	var v seaweedfsVolume

	for key, val := range r.Options {
		switch key {
		default:
			if val != "" {
				v.Options = append(v.Options, key+"="+val)
			} else {
				v.Options = append(v.Options, key)
			}
		}
	}

	v.Name = r.Name

	if err := updateVolumeInfo(v); err != nil {
		return err
	}

	return nil
}

// Remove the specified volume from disk. This request is issued when a
// user invokes docker rm -v to remove volumes associated with a container.
func (d *seaweedfsDriver) Remove(r *volume.RemoveRequest) error {
	logrus.WithField("method", "remove").Debugf("%#v", r)

	v, err := getVolumeInfo(r.Name)
	if err != nil {
		return logError("volume %s not found", r.Name)
	}

	if v.connections() != 0 {
		return logError("volume %s is currently used by a container", r.Name)
	}

	// if we unmount before the removeall, the data is kept in seaweedfs
	if err = d.unmountVolume(&v); err != nil {
		return err
	}

	if err := os.RemoveAll(v.SourcePath()); err != nil {
		logError(err.Error())
	}
	removeVolumeInfo(r.Name)
	return nil
}

// Path requests the path to the volume with the given volume_name.
func (d *seaweedfsDriver) Path(r *volume.PathRequest) (*volume.PathResponse, error) {
	logrus.WithField("method", "path").Debugf("%#v", r)

	v, err := getVolumeInfo(r.Name)
	if err != nil {
		return &volume.PathResponse{}, logError("volume %s not found", r.Name)
	}

	return &volume.PathResponse{Mountpoint: filepath.Join(getPluginDir(), "rootfs", v.MountPath())}, nil
}

// Mount is called once per container start.
// If the same volume_name is requested more than once, the plugin may need to keep
// track of each new mount request and provision at the first mount request and
// deprovision at the last corresponding unmount request.
// Docker requires the plugin to provide a volume, given a user specified volume name.
// ID is a unique ID for the caller that is requesting the mount.
func (d *seaweedfsDriver) Mount(r *volume.MountRequest) (*volume.MountResponse, error) {
	logrus.WithField("method", "mount").Debugf("%#v", r)

	v, err := getVolumeInfo(r.Name)
	if err != nil {
		return &volume.MountResponse{}, logError("volume %s not found", r.Name)
	}
	logrus.WithField("volume-info", r.Name).Debugf("%#v", v)

	// TODO: don't count connections, actually check to see if the mount is setup, and if not, try again.
	mounted, err := IsMounted("filer:8888:"+v.SourcePath(), v.MountPath())
	if err != nil {
		logrus.Infof("IsMounted(%s, %s) returned error: %s", "filer:8888:"+v.SourcePath(), v.MountPath(), err)
	}
	if !mounted {
		logrus.Infof("Mounting to %s", v.MountPath())
		fi, err := os.Lstat(v.SourcePath())
		if os.IsNotExist(err) {
			if err := os.MkdirAll(v.SourcePath(), 0755); err != nil {
				return &volume.MountResponse{}, logError(err.Error())
			}
		} else if err != nil {
			return &volume.MountResponse{}, logError(err.Error())
		}

		if fi != nil && !fi.IsDir() {
			return &volume.MountResponse{}, logError("%v already exists and it's not a directory", v.SourcePath())
		}

		if err := d.mountVolume(&v); err != nil {
			return &volume.MountResponse{}, logError(err.Error())
		}

		// TODO: wait for the mount to be confirmed as successful, or timeout and return error

	}

	v.addConnection(r.ID)
	if err = updateVolumeInfo(v); err != nil {
		logrus.WithField("method", "mount").WithField("updateVolumeInfo ERROR", err).Errorf("%#v", v)
	} else {
		logrus.WithField("method", "mount").WithField("updateVolumeInfo", r.Name).Debugf("%#v", v)
	}

	return &volume.MountResponse{Mountpoint: filepath.Join(getPluginDir(), "rootfs", v.MountPath())}, nil
}

// Docker is no longer using the named volume.
// Unmount is called once per container stop.
// Plugin may deduce that it is safe to deprovision the volume at this point.
// ID is a unique ID for the caller that is requesting the mount.
func (d *seaweedfsDriver) Unmount(r *volume.UnmountRequest) error {
	logrus.WithField("method", "unmount").Debugf("%#v", r)

	v, err := getVolumeInfo(r.Name)
	if err != nil {
		return logError("volume %s not found", r.Name)
	}

	v.delConnection(r.ID)

	// TODO: OMG - how to make a shared concept of this??
	// TODO: I think it might be easier to not unmount until there are no more nodes using it (for now)
	//       Later, can keep a hash of how many mounts on each node...
	err = updateVolumeInfo(v)
	if err = updateVolumeInfo(v); err != nil {
		logrus.WithField("updateVolumeInfo ERROR", err).Errorf("%#v", v)
	} else {
		logrus.WithField("updateVolumeInfo", r.Name).Debugf("%#v", v)
	}

	// get some interesting speedups by keeping the fusemount container running
	return nil

	if v.connections() <= 0 {
		updateVolumeInfo(v)

		if err = d.unmountVolume(&v); err != nil {
			return err
		}
	}

	return nil
}

func (d *seaweedfsDriver) unmountVolume(v *seaweedfsVolume) error {
	ctx := context.Background()
	cli, err := GetDockerClient(ctx, "")
	if err != nil {
		return err
	}

	volumeContainer := "seaweed-volume-plugin-" + v.Name
	logrus.Debugf("Unmount(%s) requested", v.SourcePath())

	execID, err := cli.ContainerExecCreate(ctx,
		volumeContainer,
		types.ExecConfig{
			User:         "0",
			Privileged:   false,
			Tty:          false,
			AttachStdin:  false,
			AttachStderr: true,
			AttachStdout: true,
			Detach:       false,
			DetachKeys:   "",
			Env:          []string{},
			Cmd:          []string{"umount", v.MountPath()},
		},
	)
	if err != nil {
		logError("Unmount ExecCreate: %s", err)
	} else {
		resp, err := cli.ContainerExecAttach(ctx,
			execID.ID,
			types.ExecStartCheck{
				Detach: false,
				Tty:    false,
			},
		)
		if err != nil {
			logError("Unmount ExecAttach: %s", err)
		} else {
			//read with timeout, and if its hung, kill it with fire
			resp.Conn.SetDeadline(time.Now().Add(time.Second * 5))
			b, err := ioutil.ReadAll(resp.Reader)
			logrus.Debugf("unmount(%s): (Err: %s ) Output: %s", v.SourcePath(), err, b)
			if err != nil {
				logError("Unmount ReadAttach: %s", err)
			}
		}
	}

	stats, err := cli.ContainerInspect(ctx, volumeContainer)
	if err != nil {
		return logError("Unmount ContainerInspect: %s", err)
	}
	logrus.Debugf("ContainerInspect: %#v", stats)

	// if err := cli.ContainerRemove(ctx,
	// 	stats.ID,
	// 	types.ContainerRemoveOptions{
	// 		RemoveVolumes: true,
	// 		RemoveLinks:   true,
	// 		Force:         true,
	// 	},
	// ); err != nil {
	// 	return logError("Unmount ContainerRemove: %s", err)
	// }
	return nil
}

// Get info about volume_name.
func (d *seaweedfsDriver) Get(r *volume.GetRequest) (*volume.GetResponse, error) {
	logrus.WithField("method", "get").Debugf("%#v", r)

	v, err := getVolumeInfo(r.Name)
	if err != nil {
		return &volume.GetResponse{}, logError("volume %s not found", r.Name)
	}

	logrus.WithField("get", "volumeinfo").Debugf("%#v", v)

	return &volume.GetResponse{Volume: &volume.Volume{
		Name:       r.Name,
		Mountpoint: filepath.Join(getPluginDir(), "rootfs", v.MountPath()),
	}}, nil
}

// List of volumes registered with the plugin.
func (d *seaweedfsDriver) List() (*volume.ListResponse, error) {
	logrus.WithField("method", "list").Debugf("version %s, build %s, branch: %s\n", Version, CommitHash, BranchName)

	var vols []*volume.Volume
	entries, err := listVolumes()
	if err != nil {
		return &volume.ListResponse{Volumes: vols}, err
	}
	for _, volName := range entries {
		// v, err := getVolumeInfo(pair.Key) // TODO: extract this / just unmarshal the json..
		// if err != nil {
		// 	return &volume.ListResponse{Volumes: vols}, err
		// }
		thisVol := volume.Volume{
			Name:       volName,
			Mountpoint: filepath.Join(getPluginDir(), "rootfs", MountPath(volName)),
		}
		vols = append(vols, &thisVol)
		logrus.WithField("list", volName).Debugf("returns %#v\n", thisVol)
	}

	return &volume.ListResponse{Volumes: vols}, nil
}

// Get the list of capabilities the driver supports.
// The driver is not required to implement Capabilities. If it is not implemented, the default values are used.
func (d *seaweedfsDriver) Capabilities() *volume.CapabilitiesResponse {
	logrus.WithField("method", "capabilities").Debugf("version %s, build %s, branch: %s\n", Version, CommitHash, BranchName)

	return &volume.CapabilitiesResponse{Capabilities: volume.Capability{Scope: "local"}}
}

func (d *seaweedfsDriver) mountVolume(v *seaweedfsVolume) error {
	logrus.WithField("method", "mountVolume").Debugf("volinfo: %#v", *v)

	// TODO: need to do something with the options (uid mapping would rock)
	// for _, option := range v.Options {
	// 	cmd.Args = append(cmd.Args, "-o", option)
	// }

	// TODO: to make a mount available to a different user
	os.MkdirAll(v.SourcePath(), 0777)
	var userOpt, gidOpt, uMask string
	for _, option := range v.Options {
		//cmd.Args = append(cmd.Args, "-o", option)
		if strings.HasPrefix(option, "uid=") {
			userOpt = strings.TrimPrefix(option, "uid=")
		}
		if strings.HasPrefix(option, "gid=") {
			gidOpt = strings.TrimPrefix(option, "gid=")
		}
		if strings.HasPrefix(option, "umask=") {
			uMask = strings.TrimPrefix(option, "umask=")
		}
		logrus.Debugf("option: (%s)", option)
	}
	uid, gid := 0, 0
	if userOpt != "" {
		logrus.Debugf("userOpt: (%s)", userOpt)
		u, err := user.Lookup(userOpt)
		if err != nil {
			u, err = user.LookupId(userOpt)
		}
		user := userOpt
		group := gidOpt
		if err == nil && u != nil {
			user = u.Uid
			if group != "" {
				group = u.Gid
			}
		}

		logrus.Debugf("u: (%#v)", u)
		if parsedID, pe := strconv.ParseUint(user, 10, 32); pe == nil {
			uid = int(parsedID)
		}
		if parsedID, pe := strconv.ParseUint(group, 10, 32); pe == nil {
			gid = int(parsedID)
		}
		logrus.Debugf("chown: (%s, %d, %d)", v.SourcePath(), uid, gid)
		os.Chown(v.SourcePath(), uid, gid)

	}
	fi, _ := os.Lstat(v.SourcePath())
	mode := fi.Mode()
	if uMask != "" {
		if parsedID, pe := strconv.ParseUint(uMask, 8, 32); pe == nil {
			mode = os.FileMode(parsedID)
			logrus.Debugf("chmod(%s, %#o)", v.SourcePath(), mode)

			os.Chmod(v.SourcePath(), mode)

			fi, _ := os.Lstat(v.SourcePath())
			logrus.Debugf("mode(%s): %v\n", fi.Mode(), v.SourcePath())
		}
	}

	// TODO: what should we do if there already is one - atm, the output to the user "ok"
	// the error maybe should be to tell them there is somethign wrong, and they might be able to fix it
	// if they force kill the plugin-vol (so long as its not yet in use?) - and then remove the mount point, and ???
	// OR if the settings are right, we could just reuse it?

	containerName := "seaweed-volume-plugin-" + v.Name

	// This starts a new container because the non-swarm service mode plugin doesn't get access to the seaweedfs stack
	// TODO: can probably bring this inside this container now that we're a swarm service, but IDK what's easier to debug...
	// TODO: it might also be nice for it to be a service, IDK what the pros/cons are.
	_, err := runContainer(
		&container.Config{
			Image:      imageName,
			User:       fmt.Sprintf("%d", uid),
			Entrypoint: []string{"weed"},
			Cmd: []string{
				"-v", "2",
				"mount",
				"-filer=filer:8888",
				"-filer.path=" + v.SourcePath(),
				"-dir=" + v.MountPath(),
			},
		},
		&container.HostConfig{
			//AutoRemove: true,
			//Priviledged: true,
			CapAdd: []string{"SYS_ADMIN"},
			Resources: container.Resources{
				Devices: []container.DeviceMapping{container.DeviceMapping{
					PathOnHost:        "/dev/fuse",
					PathInContainer:   "/dev/fuse",
					CgroupPermissions: "rwm", // needs Cap=SYS_ADMIN
				}},
			},
			Mounts: []mount.Mount{
				{
					Type: mount.TypeBind,
					// TODO: figure out what the propagated-mount dir is (it works when the plugin is installed, but not using plain containers)
					//Source:   getPluginDir() + "/propagated-mount/",
					Source:   getPluginDir() + "/rootfs/mnt/docker-volumes/",
					Target:   "/mnt/docker-volumes/",
					ReadOnly: false,
					BindOptions: &mount.BindOptions{
						Propagation:  mount.PropagationRShared,
						NonRecursive: false,
					},
				}},
			SecurityOpt: []string{"apparmor=unconfined"},
		},
		&network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				"seaweedfs_internal": {},
			},
		},
		containerName,
	)
	logrus.WithField("method", "mountVolume").WithField("image", imageName).Debugf("Starting %s", containerName)
	if err != nil {
		return logError("Error runing Container: %s", err)
	}
	// TODO: test that we have actually mounted

	dataDir := v.MountPath()
	os.MkdirAll(dataDir, mode)
	os.Chown(dataDir, uid, gid)

	return nil
}

var pluginDir = ""

func getPluginDir() string {
	if pluginDir != "" {
		return pluginDir
	}
	// write a unique filename to /tmp
	content := []byte("temporary file's content")
	tmpfile, err := ioutil.TempFile("/tmp", "example")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write(content); err != nil {
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}
	// start a container with access to /var/lib/docker/plugins/ and search for that file in */rootfs/tmp
	filename := strings.TrimPrefix(tmpfile.Name(), "/tmp/")

	containerID, err := runContainer(
		&container.Config{
			Image:      "svendowideit/seaweedfs-volume-plugin-rootfs:" + BranchName,
			Entrypoint: []string{"find"},
			Cmd:        []string{"/var/lib/docker/plugins/", "-name", filename},
		},
		&container.HostConfig{
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: "/var/lib/docker/plugins/",
					Target: "/var/lib/docker/plugins/",
				}},
		},
		&network.NetworkingConfig{},
		"",
	)
	if err != nil {
		logError("Error runing Container: %s", err)
		return ""
	}

	// TODO: it'd be nice not to need this more than once
	ctx := context.Background()
	cli, err := GetDockerClient(ctx, "")
	if err != nil {
		logError("Error getting Docker client: %s", err)
		return ""
	}
	// defer func() {
	// 	if err := cli.ContainerRemove(ctx,
	// 		containerID,
	// 		types.ContainerRemoveOptions{
	// 			RemoveVolumes: true,
	// 			RemoveLinks:   true,
	// 			Force:         true,
	// 		},
	// 	); err != nil {
	// 		logError("findPlugin ContainerRemove(%s): %s", containerID, err)
	// 	}
	// }()

	statusCh, errCh := cli.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			logError("Error waiting for Container: %s", err)
			return ""
		}
	case <-statusCh:
	}

	out, err := cli.ContainerLogs(ctx, containerID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		logError("Error creating Container: %s", err)
		return ""
	}
	//stdcopy.StdCopy(os.Stdout, os.Stderr, out)
	output, err := ioutil.ReadAll(out)
	logrus.Debugf("Find file (%s): (Err: %s ) Output: %s", filename, err, output)
	// TODO: find out why there's leading unicode in output..
	// ' \\x01\\x00\\x00\\x00\\x00\\x00\\x00u/var/lib/docker/plug....'
	if err != nil {
		logError("FindFile: %s", err)
		return ""
	}

	pluginDir = strings.TrimSpace(string(output))
	// remove the leading unicode
	pluginDir = pluginDir[strings.Index(pluginDir, "/var/lib/docker/plugins/"):]
	pluginDir = strings.TrimSuffix(pluginDir, "/rootfs"+tmpfile.Name())
	logrus.Debug(pluginDir)
	return pluginDir
}

func logError(format string, args ...interface{}) error {
	logrus.Errorf(format, args...)
	return fmt.Errorf(format, args...)
}

func runCmd(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	logrus.Debug(cmd.Args)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Debugf("seaweedfs command execute failed: %v (%s)", err, output)
		return "", err
	}
	return string(output), nil
}

// TODO: detect what other versions of the plugin is running (locally and on other nodes)
// TODO: make sure we can access docker socket, and that we're actually at the plugin socket we think we are
// TODO: may need to figure out if installing as a swarm plugin also gives me access to the seaweedfs_internal network:
//       https://github.com/moby/moby/blob/master/integration/service/plugin_test.go#L109
func main() {
	imageName = "svendowideit/seaweedfs-volume-plugin-rootfs:" + BranchName

	defer func() {
		logrus.Infof("Caught signal, cleaning up\n")
		os.Remove(socketAddress)
	}()

	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt)
	defer done()
	ctx, tdone := signal.NotifyContext(ctx, syscall.SIGTERM)
	defer tdone()

	debug := os.Getenv("DEBUG")
	if ok, _ := strconv.ParseBool(debug); ok {
		logrus.SetLevel(logrus.DebugLevel)
	}
	logrus.Infof("Version %s, build %s, branch: %s\n", Version, CommitHash, BranchName)

	pluginDir := getPluginDir()
	logrus.Infof("Plugin dir: %s", pluginDir)

	_, err := os.Lstat("/run/docker.sock")
	if os.IsNotExist(err) {
		log.Fatal(err)
	}

	d, err := newseaweedfsDriver("/mnt")
	if err != nil {
		log.Fatal(err)
	}

	h := volume.NewHandler(d)

	logrus.Infof("no-ctx listening on %s", socketAddress)

	go func() {
		logrus.Error(h.ServeUnix(socketAddress, 0))
	}()

	logrus.Infof("Waiting for SIGTERM")

	<-ctx.Done()
}
