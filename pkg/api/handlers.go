package api

import (
	"context"
	"fmt"
	"log"
	"tunnel/pkg/configurer"

	"github.com/google/uuid"
	"github.com/swaggest/usecase/status"
	"gopkg.in/yaml.v2"
)

type ConnectGetOutput struct {
	ConnectionConfig string `json:"connection_config"`
}

func (s APIService) ConnectGet(ctx context.Context, input struct{}, output *ConnectGetOutput) error {
	node := configurer.NebulaNode{
		Name:           uuid.New().String(),
		Groups:         "client",
		Punch:          false,
		AmRelay:        false,
		UseRelays:      false,
		UseTUN:         false,
		TUNDevName:     "",
		AcceptOutbound: false,
		AcceptInbound:  true,
	}

	ip, err := s.IPAMService.NextIP()
	if err != nil {
		log.Fatalf("get next ip: %v", err)
	}
	ipCIDR, err := s.IPAMService.JoinIPAndNet(ip)

	connCfg, err := node.CreateConfig(s.CACert, s.CAKey, ipCIDR)
	if err != nil {
		return status.Wrap(fmt.Errorf("creating nebula cfg: %w", err), status.Internal)
	}

	serverAddr, err := s.IPAMService.ServerAddr()
	if err != nil {
		return status.Wrap(fmt.Errorf("getting server addr: %w", err), status.Internal)
	}

	// TODO: make this more configurable
	if err = configurer.ApplyStaticHosts(connCfg, map[string][]string{
		serverAddr: []string{
			s.NebulaPublicAddr,
		},
	}); err != nil {
		return status.Wrap(fmt.Errorf("apply static hosts: %w", err), status.Internal)
	}

	// TODO: make this more configurable; add actual lighthouses support (?)
	if err = configurer.ApplyLighthouseHosts(connCfg, []string{
		serverAddr,
	}); err != nil {
		return status.Wrap(fmt.Errorf("apply lighthouse hosts: %w", err), status.Internal)
	}

	connCfgBytes, err := yaml.Marshal(connCfg.Settings)
	if err != nil {
		return status.Wrap(fmt.Errorf("marshal yaml conn cfg: %w", err), status.Internal)
	}

	output.ConnectionConfig = string(connCfgBytes)

	return nil
}

type TokenGetOutput struct {
	OntTimeToken string `json:"one_time_token"`
}

func (s APIService) TokenGet(ctx context.Context, input struct{}, output *TokenGetOutput) error {
	return nil
}
