//
// Copyright (C) 2014-2017 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"k8s.io/klog/v2"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"github.com/coreos/go-systemd/daemon"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/pkg/server"
)

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)

	var opts struct {
		ConfigFile      string `short:"f" long:"config-file" description:"specifying a config file"`
		ConfigType      string `short:"t" long:"config-type" description:"specifying config type (toml, yaml, json)" default:"toml"`
		LogLevel        string `short:"l" long:"log-level" description:"specifying log level"`
		LogPlain        bool   `short:"p" long:"log-plain" description:"use plain format for logging (json by default)"`
		UseSyslog       string `short:"s" long:"syslog" description:"use syslogd"`
		Facility        string `long:"syslog-facility" description:"specify syslog facility"`
		DisableStdlog   bool   `long:"disable-stdlog" description:"disable standard logging"`
		CPUs            int    `long:"cpus" description:"specify the number of CPUs to be used"`
		GrpcHosts       string `long:"api-hosts" description:"specify the hosts that gobgpd listens on" default:":50052"`
		GracefulRestart bool   `short:"r" long:"graceful-restart" description:"flag restart-state in graceful-restart capability"`
		Dry             bool   `short:"d" long:"dry-run" description:"check configuration"`
		PProfHost       string `long:"pprof-host" description:"specify the host that gobgpd listens on for pprof" default:"localhost:6060"`
		PProfDisable    bool   `long:"pprof-disable" description:"disable pprof profiling"`
		UseSdNotify     bool   `long:"sdnotify" description:"use sd_notify protocol"`
		TLS             bool   `long:"tls" description:"enable TLS authentication for gRPC API"`
		TLSCertFile     string `long:"tls-cert-file" description:"The TLS cert file"`
		TLSKeyFile      string `long:"tls-key-file" description:"The TLS key file"`
		Version         bool   `long:"version" description:"show version number"`
	}
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}
	if len(opts.ConfigFile) == 0 {
		klog.Fatal("config-file is required")
	}

	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.JSONFormatter{})

	maxSize := 256 << 20 // 256MB
	grpcOpts := []grpc.ServerOption{grpc.MaxRecvMsgSize(maxSize), grpc.MaxSendMsgSize(maxSize)}
	log.Info("gobgpd started")
	bgpServer := server.NewBgpServer(server.GrpcListenAddress(opts.GrpcHosts), server.GrpcOption(grpcOpts)) // localhost:50051
	go bgpServer.Serve()
	defer stopServer(bgpServer, opts.UseSdNotify)

	initialConfig, err := ReadConfigFile(opts.ConfigFile, opts.ConfigType)
	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "Config",
			"Error": err,
		}).Fatalf("Can't read config file %s", opts.ConfigFile)
	}
	log.WithFields(log.Fields{
		"Topic": "Config",
	}).Info("Finished reading the config file")

	currentConfig, err := InitialConfig(context.Background(), bgpServer, initialConfig, opts.GracefulRestart)
	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "Config",
			"Error": err,
		}).Fatalf("Failed to apply initial configuration %s", opts.ConfigFile)
	}

	signal.Notify(sigCh, syscall.SIGHUP)
	for sig := range sigCh {
		if sig != syscall.SIGHUP {
			stopServer(bgpServer, opts.UseSdNotify)
			return
		}

		log.WithFields(log.Fields{
			"Topic": "Config",
		}).Info("Reload the config file")
		newConfig, err := ReadConfigFile(opts.ConfigFile, opts.ConfigType)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Config",
				"Error": err,
			}).Warningf("Can't read config file %s", opts.ConfigFile)
			continue
		}

		currentConfig, err = UpdateConfig(context.Background(), bgpServer, currentConfig, newConfig)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Config",
				"Error": err,
			}).Warningf("Failed to update config %s", opts.ConfigFile)
			continue
		}
	}
}

func stopServer(bgpServer *server.BgpServer, useSdNotify bool) {
	bgpServer.StopBgp(context.Background(), &api.StopBgpRequest{})
	if useSdNotify {
		daemon.SdNotify(false, daemon.SdNotifyStopping)
	}
}
