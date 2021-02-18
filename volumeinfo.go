package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	//"sync"
	"time"

	"github.com/linxGnu/goseaweedfs"
	"github.com/sirupsen/logrus"
)

// prefix for volume info
var keyPrefix = "/docker-seaweedfs-plugin/"

// on disk structure:
// $keyPrefix/<volName>/   <- denotes a volume exists
// $keyPrefix/<volName>/json   <- file with json encoded seaweedfsVolume
// $keyPrefix/<volName>/connections/<containername>   <- denotes that the volume is mounted by this container

type seaweedfsVolume struct {
	Options []string
	Name    string
}

func SourcePath(volName string) string {
	return filepath.Join("/mnt/docker-volumes", volName)
}
func MountPath(volName string) string {
	return filepath.Join(SourcePath(volName), "_data")
}
func (v seaweedfsVolume) SourcePath() string {
	return SourcePath(v.Name)
}
func (v seaweedfsVolume) MountPath() string {
	return filepath.Join(v.SourcePath(), "_data")
}
func (v seaweedfsVolume) connections() int {
	c, _ := listConnections(v.Name)

	return len(c)
}
func (v seaweedfsVolume) addConnection(req string) error {
	f, err := getStore()
	if err != nil {
		return err
	}

	r := strings.NewReader(req)

	result, err := f.Upload(r, int64(r.Size()), keyPrefix+v.Name+"/connections/"+req, "", "")
	if err != nil {
		fmt.Errorf("Error trying to addConnection: %s, %v", v.Name, err)
	}
	logrus.WithField("addConnection", v.Name).Debugf("returns %#v\n", result)

	return err
}
func (v seaweedfsVolume) delConnection(req string) error {
	f, err := getStore()
	if err != nil {
		return err
	}

	err = f.Delete(keyPrefix+v.Name+"/connections/"+req, nil)
	if err != nil {
		fmt.Errorf("Error trying to delConnection: %s, %v", v.Name, err)
	}
	return err
}

func listConnections(volName string) (connections []string, err error) {
	f, err := getStore()
	if err != nil {
		logrus.WithField("listConnections", len(connections)).
			Debugf("getStore returns error: %#v\n", err)
		return connections, err
	}
	files, err := f.ListDir(keyPrefix + volName + "/connections/")
	if err != nil {
		logrus.WithField("listConnections", len(connections)).
			Debugf("ListDir returns error: %#v\n", err)
		return connections, err
	}
	for _, f := range files {
		if f.IsDir {
			connections = append(connections, f.Name)
		}
	}
	logrus.WithField("listConnections", len(connections)).
		Debugf("success: returns %#v\n", connections)

	return connections, err
}

func getStore() (f *goseaweedfs.Filer, err error) {
	// TODO: make that configurable
	filerUrl := "http://filer:8888"
	httpClient := http.Client{Timeout: 5 * time.Minute}
	f, err = goseaweedfs.NewFiler(filerUrl, &httpClient)
	if err != nil {
		log.Fatal("Cannot create filer connection (%s)", err)
		return f, err
	}
	return f, nil
}

func listVolumes() (vol []string, err error) {
	f, err := getStore()
	if err != nil {
		logrus.WithField("listVolumes", len(vol)).
			Debugf("getStore returns error: %#v\n", err)
		return vol, err
	}
	files, err := f.ListDir(keyPrefix)
	if err != nil {
		logrus.WithField("listVolumes", len(vol)).
			Debugf("ListDir returns error: %#v\n", err)
		return vol, err
	}
	for _, f := range files {
		if f.IsDir {
			vol = append(vol, f.Name)
		}
	}
	logrus.WithField("listVolumes", len(vol)).
		Debugf("success: returns %#v\n", vol)

	return vol, err
}

func getVolumeInfo(name string) (vol seaweedfsVolume, err error) {
	f, err := getStore()
	if err != nil {
		logrus.WithField("getVolumeInfo", name).
			Debugf("getStore returns error: %#v\n", err)
		return vol, err
	}

	path := keyPrefix + name + "/json"
	data, status, err := f.Get(path, nil, nil)
	if err != nil {
		logrus.WithField("getVolumeInfo", name).
			Debugf("Get(%s) returns error: %#v\n", path, err)
		return vol, err
	}
	logrus.WithField("get", name).WithField("status", status).Debugf("returns %#v\n", string(data))
	if status < 200 || status > 299 {
		logrus.WithField("getVolumeInfo", name).
			Debugf("volume %s not found (status: %d)", name, status)
		return vol, fmt.Errorf("volume %s not found (status: %d)", name, status)
	}

	if err := json.Unmarshal(data, &vol); err != nil {
		logrus.WithField("getVolumeInfo", name).
			Debugf("Unmarshal(%s) returns error: %#v\n", data, err)
		return vol, err
	}

	logrus.WithField("get", name).Debugf("success %#v\n", vol)
	return vol, err
}

func updateVolumeInfo(vol seaweedfsVolume) error {
	f, err := getStore()
	if err != nil {
		return err
	}

	data, err := json.Marshal(vol)
	if err != nil {
		logrus.WithField("vol", vol).Error(err)
		return err
	}

	r := bytes.NewReader(data)

	result, err := f.Upload(r, int64(r.Size()), keyPrefix+vol.Name+"/json", "", "")
	if err != nil {
		fmt.Errorf("Error trying to put value at key: %v", vol.Name)
	}
	logrus.WithField("upload", vol.Name).Debugf("returns %#v\n", result)

	return err
}

func removeVolumeInfo(name string) (err error) {
	// f, err := getStore()
	// if err != nil {
	// 	return err
	// }

	// err = f.Delete(keyPrefix+name, nil)
	// if err != nil {
	// 	fmt.Errorf("Error trying to delete key: %v", name)
	// }
	logrus.WithField("removeVolumeInfo", name).Debugf("ignoring remove - I think it causes weird issues")

	return err
}
