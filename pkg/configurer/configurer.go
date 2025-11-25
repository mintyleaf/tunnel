package configurer

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"tunnel/pkg/cert"

	"github.com/slackhq/nebula/config"
)

type NebulaNode struct {
	Name   string
	Groups string

	Punch bool

	AmRelay   bool
	UseRelays bool

	UseTUN     bool
	TUNDevName string

	AcceptOutbound bool
	AcceptInbound  bool
}

var mappingRegex = regexp.MustCompile(`^(\d+):(.*):(tcp|udp|both)$`)

func ApplyLighthouseHosts(c *config.C, hosts []string) error {
	(*c).Settings["lighthouse"] = map[string][]string{
		"hosts": hosts,
	}
	return nil
}

func ApplyStaticHosts(c *config.C, hosts map[string][]string) error {
	(*c).Settings["static_host_map"] = hosts
	return nil
}

func ApplyPortMappings(c *config.C, portMappings []string) error {
	portMappingSlice := []any{}

	for _, portMapping := range portMappings {
		matches := mappingRegex.FindStringSubmatch(portMapping)
		if len(matches) != 4 {
			return fmt.Errorf("invalid port mapping format: '%s'. expected format: PORT:DIAL_ADDRESS:tcp/udp/both", portMapping)
		}

		portStr := matches[1]
		host := strings.TrimSpace(matches[2])
		protoStr := matches[3]

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid port number in mapping '%s': %w", portMapping, err)
		}
		// TODO: proper host check
		if host == "" {
			return fmt.Errorf("DIAL_ADDRESS cannot be empty in mapping '%s'", portMapping)
		}

		var protocols []string
		switch protoStr {
		case "tcp":
			protocols = []string{"tcp"}
		case "udp":
			protocols = []string{"udp"}
		case "both":
			protocols = []string{"tcp", "udp"}
		default:
			return fmt.Errorf("invalid protocol '%s' in mapping '%s'. must be tcp, udp, or both", protoStr, portMapping)
		}

		protocolsAny := make([]any, len(protocols))
		for i, p := range protocols {
			protocolsAny[i] = p
		}

		portMappingSlice = append(portMappingSlice, map[string]any{
			"listen_port":  port,
			"dial_address": host,
			"protocols":    protocolsAny,
		})
	}

	(*c).Settings["port_forwarding"] = map[string]any{
		"inbound": portMappingSlice,
	}

	return nil
}

func ApplyListen(c *config.C, listenAddr string) error {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("splitting address %s: %w", listenAddr, err)
	}
	// ipv6 can be in [::]:PORT format
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")

	(*c).Settings["listen"] = map[string]any{
		"host": host,
		"port": port,
	}
	return nil
}

func (node NebulaNode) CreateConfig(
	caCert, caKey, ip string,
) (*config.C, error) {
	c := config.NewC(nil)

	serverKeyPair, err := cert.GenerateKeyPair()
	if err != nil {
		log.Fatalf("server key pair: %v", err)
	}

	serverCertPair, err := cert.SignCert(
		caCert,
		caKey,
		node.Name,
		ip,
		node.Groups,
		serverKeyPair.CertPEM,
	)
	if err != nil {
		return nil, fmt.Errorf("server cert pair: %w", err)
	}
	(*c).Settings["pki"] = map[string]any{
		"cert": serverCertPair.CertPEM,
		"key":  serverKeyPair.KeyPEM,
		"ca":   caCert,
	}

	(*c).Settings["punchy"] = map[string]any{
		"punch": node.Punch,
	}
	(*c).Settings["relay"] = map[string]any{
		"am_relay":   node.AmRelay,
		"use_relays": node.UseRelays,
	}

	(*c).Settings["tun"] = map[string]any{
		"disabled": !node.UseTUN,
		"dev":      node.TUNDevName,
	}

	// TODO: make this more configurable
	(*c).Settings["firewall"] = map[string]any{
		"outbound": []any{
			map[string]any{
				"port":  "any",
				"proto": "any",
				"host":  "any",
			},
		},
		"inbound": []any{
			map[string]any{
				"port":  "any",
				"proto": "any",
				"host":  "any",
			},
		},
	}
	firewallRef, ok := (*c).Settings["firewall"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("failed to get firewall ref: %w", err)
	}
	if !node.AcceptInbound {
		delete(firewallRef, "inbound")
	}
	if !node.AcceptOutbound {
		delete(firewallRef, "outbound")
	}

	return c, nil
}
