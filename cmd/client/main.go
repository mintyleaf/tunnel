package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"tunnel/internal/config"
	"tunnel/pkg/api"
	"tunnel/pkg/configurer"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	nebulaConfig "github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/port_forwarder"
	"github.com/slackhq/nebula/service"
	"github.com/slackhq/nebula/util"
	"gopkg.in/yaml.v2"
)

type Config struct {
	APIAddr          string `env:"API_ADDR" flag:"api-addr" default:"http://127.0.0.1:8080" usage:"tunnel server http api addr"`
	NebulaListenAddr string `env:"NEBULA_LISTEN_ADDR" flag:"nebula-listen-addr" default:"0.0.0.0:4243" usage:"nebula tunnel control listen address"`

	ConnectionCfgPath string   `env:"CONN_CFG_PATH" flag:"conn-cfg-path" default:"conn.yaml" usage:"path to the tunnel connection data"`
	PortMappings      []string `env:"PORT_MAPPINGS" flag:"port-mapping" usage:"PORT:DIAL_ADDRESS:tcp/udp/both formatted port mappings"`

	Token string `env:"TOKEN" flag:"token" default:"" usage:"one-time/master token used for initial connection"`
}

func main() {
	err := godotenv.Load()
	if err != nil && !os.IsNotExist(err) {
		log.Printf("[WARN] loading .env: %v", err)
	}

	cfg := Config{}
	if err = config.LoadConfig(&cfg); err != nil {
		log.Fatalf("failed to parse config: %v", err)
	}

	l := logrus.New()
	l.Out = os.Stdout

	connCfg := nebulaConfig.NewC(l)

	_, connCfgErr := os.Stat(cfg.ConnectionCfgPath)
	if os.IsNotExist(connCfgErr) {
		// TODO security, move that call to the api package
		resp, err := http.Get(cfg.APIAddr + "/connect")
		if err != nil {
			log.Fatalf("making http request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("non-OK status code: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("reading response body: %v", err)
		}

		var output api.ConnectGetOutput
		if err := json.Unmarshal(body, &output); err != nil {
			log.Fatalf("unmarshaling JSON response: %v\nresponse Body: %s", err, body)
		}

		connCfg.LoadString(output.ConnectionConfig)

		connCfgBytes, err := yaml.Marshal(connCfg.Settings)
		if err != nil {
			log.Fatal("marshal yaml conn cfg: %v", err)
		}
		if err := os.WriteFile(cfg.ConnectionCfgPath, connCfgBytes, 0644); err != nil {
			log.Fatalf("save conn cfg to %s: %v", cfg.ConnectionCfgPath, err)
		}
	} else {
		connCfg.Load(cfg.ConnectionCfgPath)
	}

	err = configurer.ApplyListen(connCfg, cfg.NebulaListenAddr)
	if err != nil {
		log.Fatalf("apply listen params: %v", err)
	}

	err = configurer.ApplyPortMappings(connCfg, cfg.PortMappings)
	if err != nil {
		log.Fatalf("apply port mappings: %v", err)
	}

	ctrl, err := nebula.Main(connCfg, false, "tunnel", l, overlay.NewUserDeviceFromConfig)
	if err != nil {
		log.Fatalf("nebula main: %v", err)
	}

	service, err := service.New(ctrl)
	if err != nil {
		util.LogWithContextIfNeeded("Failed to create service", err, l)
		os.Exit(1)
	}

	fwdList := port_forwarder.NewPortForwardingList()
	if err := port_forwarder.ParseConfig(l, connCfg, fwdList); err != nil {
		util.LogWithContextIfNeeded("Failed to parse port forwarder config", err, l)
		os.Exit(1)
	}
	pfService, err := port_forwarder.ConstructFromInitialFwdList(service, l, &fwdList)
	if err != nil {
		util.LogWithContextIfNeeded("Failed to start", err, l)
		os.Exit(1)
	}

	pfService.Activate()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Running, press ctrl+c to shutdown...")
	<-signalChannel

	service.CloseAndWait()
}
