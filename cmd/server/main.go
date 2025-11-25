package main

import (
	"database/sql"
	"net/http"

	"log"
	"os"
	"tunnel/internal/config"
	"tunnel/pkg/api"
	"tunnel/pkg/cert"
	"tunnel/pkg/configurer"
	"tunnel/pkg/ipam"

	nebulaConfig "github.com/slackhq/nebula/config"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/util"
	"gopkg.in/yaml.v2"

	_ "github.com/lib/pq"
)

type Config struct {
	DBConn           string   `env:"DB_CONN" flag:"db-conn" default:"postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable" usage:"postgres connection string"`
	APIListenAddr    string   `env:"API_LISTEN_ADDR" flag:"api-listen-addr" default:"0.0.0.0:8080" usage:"http api listen address"`
	NebulaListenAddr string   `env:"NEBULA_LISTEN_ADDR" flag:"nebula-listen-addr" default:"0.0.0.0:4242" usage:"nebula tunnel control listen address"`
	NebulaPublicAddr string   `env:"NEBULA_PUBLIC_ADDR" flag:"nebula-public-addr" default:"127.0.0.1:4242" usage:"nebula public tunnel control address"`
	CORSAllowOrigins []string `env:"CORS_ALLOW_ORIGINS" flag:"cors-allow-origins" usage:"cors allow origins list"`

	ConnectionCfgPath string `env:"CONN_CFG_PATH" flag:"conn-cfg-path" default:"server.yaml" usage:"path to the tunnel connection data"`
	CAKeyPath         string `env:"CA_KEY_PATH" flag:"ca-key-path" default:"ca.key" usage:"path to the ca.key file"`
	CACertPath        string `env:"CA_CERT_PATH" flag:"ca-cert-path" default:"ca.cert" usage:"path to the ca.cert file"`

	MasterToken         string `env:"MASTER_TOKEN" flag:"master-token" default:"tunnel" usage:"master auth token (leave empty to disable)"`
	MasterLocalhostOnly bool   `env:"MASTER_LOCALHOST" flag:"master-localhost" default:"true" usage:"isolate one-time token generation route to localhost access only"`
	TokenAuthDisabled   bool   `env:"AUTH_DISABLE" flag:"auth-disable" default:"false" usage:"disable any auth (for testing purposes/behind reverse proxy)"`

	NetworkCIDR string `env:"NETWORK_CIDR" flag:"network-cidr" default:"10.0.0.0/8" usage:"nebula network server address and range"`
	TUNDevName  string `env:"TUN_DEV_NAME" flag:"tun-dev-name" default:"nebula1" usage:"nebula tun device name"`
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

	db, err := sql.Open("postgres", cfg.DBConn)
	if err != nil {
		log.Fatalf("open DB connection: %v", err)
	}

	ipamService := ipam.IPAMService{
		DB:          db,
		NetworkCIDR: cfg.NetworkCIDR,
	}
	ipam.InitTables(db)

	// TODO: also check file info (is dir)
	_, caKeyErr := os.Stat(cfg.CAKeyPath)
	caKeyExists := !os.IsNotExist(caKeyErr)
	_, caCertErr := os.Stat(cfg.CACertPath)
	caCertExists := !os.IsNotExist(caCertErr)

	_, connCfgErr := os.Stat(cfg.ConnectionCfgPath)
	connCfgExists := !os.IsNotExist(connCfgErr)

	l := logrus.New()
	l.Out = os.Stdout

	connCfg := nebulaConfig.NewC(l)

	if !(caKeyExists && caCertExists) {
		log.Printf("[INFO] generating new CA at %s and %s", cfg.CAKeyPath, cfg.CACertPath)

		caPair, err := cert.GenerateCA("My Awesome Org CA")
		if err != nil {
			log.Fatalf("CA generation: %v", err)
		}
		if err := os.WriteFile(cfg.CAKeyPath, []byte(caPair.KeyPEM), 0600); err != nil {
			log.Fatalf("save CA key to %s: %v", cfg.CAKeyPath, err)
		}
		if err := os.WriteFile(cfg.CACertPath, []byte(caPair.CertPEM), 0644); err != nil {
			log.Fatalf("save CA cert to %s: %v", cfg.CACertPath, err)
		}
	}
	caKeyPEM, err := os.ReadFile(cfg.CAKeyPath)
	if err != nil {
		log.Fatalf("read CA key from %s: %v", cfg.CAKeyPath, err)
	}
	caCertPEM, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		log.Fatalf("read CA cert from %s: %v", cfg.CACertPath, err)
	}

	// TODO: move out config routine
	if !connCfgExists {
		log.Printf("[INFO] generating server keypair with NetworkCIDR %s at %s", cfg.NetworkCIDR, cfg.ConnectionCfgPath)

		// TODO: make this more configurable
		node := configurer.NebulaNode{
			Name:           "server",
			Groups:         "server",
			Punch:          true,
			AmRelay:        true,
			UseRelays:      true,
			UseTUN:         true,
			TUNDevName:     cfg.TUNDevName,
			AcceptOutbound: true,
			AcceptInbound:  true,
		}

		if err = ipamService.InitializeNetwork(); err != nil {
			log.Fatalf("initiazlie ipam network: %v", err)
		}

		ip, err := ipamService.NextIP()
		if err != nil {
			log.Fatalf("get next ip: %v", err)
		}
		ipCIDR, err := ipamService.JoinIPAndNet(ip)

		connCfg, err = node.CreateConfig(string(caCertPEM), string(caKeyPEM), ipCIDR)
		if err != nil {
			log.Fatalf("creating nebula config: %v", err)
		}

		err = configurer.ApplyListen(connCfg, cfg.NebulaListenAddr)
		if err != nil {
			log.Fatalf("apply listen params: %v", err)
		}

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

	go func() {
		if err := http.ListenAndServe(cfg.APIListenAddr,
			api.NewAPIServer(
				api.AuthService{
					DB: db,

					MasterToken:         cfg.MasterToken,
					MasterLocalhostOnly: cfg.MasterLocalhostOnly,
					TokenAuthDisabled:   cfg.TokenAuthDisabled,
				},
				ipamService,
				cfg.CORSAllowOrigins,
				cfg.NebulaPublicAddr,
				string(caCertPEM), string(caKeyPEM),
			),
		); err != nil {
			log.Fatalf("serving at %s: %v", cfg.APIListenAddr, err)
		}
	}()

	ctrl, err := nebula.Main(connCfg, false, "tunnel", l, nil)
	if err != nil {
		util.LogWithContextIfNeeded("Failed to start", err, l)
		os.Exit(1)
	}

	ctrl.Start()
	ctrl.ShutdownBlock()
}
