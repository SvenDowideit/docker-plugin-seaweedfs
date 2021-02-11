package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"

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

	Name        string
	connections int
}

func Mountpoint(volName string) string {
	return filepath.Join("/mnt/docker-volumes", volName)
}
func (v seaweedfsVolume) Mountpoint() string {
	return Mountpoint(v.Name)
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
		return vol, err
	}

	data, status, err := f.Get(keyPrefix+name+"/json", nil, nil)
	if err != nil {
		fmt.Errorf("Error trying accessing volume: %v", name)
		return vol, err
	}
	logrus.WithField("get", name).WithField("status", status).Debugf("returns %#v\n", data)

	if err := json.Unmarshal(data, &vol); err != nil {
		return vol, err
	}

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

func removeVolumeInfo(name string) error {
	f, err := getStore()
	if err != nil {
		return err
	}

	err = f.Delete(keyPrefix+name, nil)
	if err != nil {
		fmt.Errorf("Error trying to delete key: %v", name)
	}

	return err
}
