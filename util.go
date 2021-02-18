package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/docker/cli/cli/connhelper"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	// TODO: beware, this is archived
)

// Worth reading: https://docs.docker.com/engine/api/v1.24/
// and https://docs.docker.com/engine/api/v1.27/#operation/ContainerCreate

func GetDockerClient(ctx context.Context, host string) (*client.Client, error) {
	// TODO: the docker-ce ssh helper requires code in the docker daemon 18.09
	//       change this to use pure ssh tunneled unix sockets so it can be any version
	var err error
	var cli *client.Client
	if host != "" {
		var helper *connhelper.ConnectionHelper

		helper, err = connhelper.GetConnectionHelper(host)
		if err != nil {
			return nil, err
		}
		cli, err = client.NewClientWithOpts(
			client.WithHost(helper.Host),
			client.WithDialContext(helper.Dialer),
		)
	} else {
		cli, err = client.NewClientWithOpts(
			client.FromEnv,
		)

	}
	if err != nil {
		return nil, err
	}
	cli.NegotiateAPIVersion(ctx)

	return cli, err
}

func runContainer(
	config *container.Config,
	hostConfig *container.HostConfig,
	networkingConfig *network.NetworkingConfig,
	containerName string,
) (string, error) {
	ctx := context.Background()
	cli, err := GetDockerClient(ctx, "")
	if err != nil {
		logError("Error getting Docker client: %s", err)
		return "", err
	}

	if container, err := cli.ContainerInspect(ctx, containerName); err == nil {
		if container.State.Running {
			return container.ID, nil
		}
		// if err := cli.ContainerRemove(ctx, container.ID, types.ContainerRemoveOptions{
		// 	RemoveVolumes: true,
		// 	RemoveLinks:   true,
		// 	Force:         true,
		// }); err != nil {
		// 	return "", err
		// }
		if err := cli.ContainerStart(ctx, container.ID, types.ContainerStartOptions{}); err != nil {
			return "", err
		}
		return container.ID, nil
	}

	reader, err := cli.ImagePull(ctx, config.Image, types.ImagePullOptions{})
	if err != nil {
		logError("Error pulling Container: %s", err)
		return "", err
	}
	//io.Copy(os.Stdout, reader)
	b, err := ioutil.ReadAll(reader)
	logrus.Debugf("ImagePull(%s): (Err: %s ) Output: %s", config.Image, err, b)
	if err != nil {
		logError("ImagePull: %s", err)
		return "", err
	}

	cResponse, err := cli.ContainerCreate(ctx,
		config,
		hostConfig,
		networkingConfig,
		containerName,
	)
	if err != nil {
		logError("Error creating Container: %s", err)
		return "", err
	}
	if err = cli.ContainerStart(ctx, cResponse.ID, types.ContainerStartOptions{}); err != nil {
		logError("Error starting Container: %s", err)
		return "", err
	}

	return cResponse.ID, nil
}

/*
 *	Checks if the given src and dst path are mounted
 *
 *
 *	courtesy: https://github.com/digitalocean/csi-digitalocean/blob/master/driver/mounter.go
 */

type findmntResponse struct {
	FileSystems []fileSystem `json:"filesystems"`
}

type fileSystem struct {
	Target      string `json:"target"`
	Propagation string `json:"propagation"`
	FsType      string `json:"fstype"`
	Options     string `json:"options"`
}

func IsMounted(sourcePath, destPath string) (bool, error) {
	if sourcePath == "" {
		return false, errors.New("source is not specified for checking the mount")
	}

	if destPath == "" {
		return false, errors.New("target is not specified for checking the mount")
	}

	findmntCmd := "findmnt"
	_, err := exec.LookPath(findmntCmd)
	if err != nil {
		if err == exec.ErrNotFound {
			return false, fmt.Errorf("%q executable not found in $PATH", findmntCmd)
		}
		return false, err
	}

	findmntArgs := []string{"-o", "TARGET,PROPAGATION,FSTYPE,OPTIONS", sourcePath, "-J"}
	out, err := exec.Command(findmntCmd, findmntArgs...).CombinedOutput()
	if err != nil {
		// findmnt exits with non zero exit status if it couldn't find anything
		if strings.TrimSpace(string(out)) == "" {
			return false, nil
		}

		return false, fmt.Errorf("checking mounted failed: %v cmd: %q output: %q",
			err, findmntCmd, string(out))
	}

	var resp *findmntResponse
	err = json.Unmarshal(out, &resp)
	if err != nil {
		return false, fmt.Errorf("couldn't unmarshal data: %q: %s", string(out), err)
	}

	targetFound := false
	for _, fs := range resp.FileSystems {
		// SD Commented out some k8s csi related stuff.
		// check if the mount is propagated correctly. It should be set to shared.
		// if fs.Propagation != "shared" {
		// 	return true, fmt.Errorf("mount propagation for target %q is not enabled or the block device %q does not exist anymore", destPath, sourcePath)
		// }

		// the mountpoint should match as well
		if fs.Target == destPath {
			targetFound = true

			_, err := os.Lstat(fs.Target)
			if err != nil {
				// we found it, but its broken - maybe we can mount over the top?
				return false, err
			}

			break
		}
	}

	return targetFound, nil
}
