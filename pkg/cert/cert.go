package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/netip"
	"strings"
	"time"

	nebulaCert "github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

type CertificatePair struct {
	CertPEM string
	KeyPEM  string
}

func GenerateCA(caName string) (*CertificatePair, error) {
	curve := nebulaCert.Curve_CURVE25519
	duration := time.Duration(time.Hour * 8760 * 10)

	pub, rawPriv, err := newSignerKeypair(curve)
	if err != nil {
		return nil, err
	}

	tbs := &nebulaCert.TBSCertificate{
		Version:        nebulaCert.Version2,
		Name:           caName,
		Groups:         nil,
		Networks:       nil,
		UnsafeNetworks: nil,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(duration),
		PublicKey:      pub,
		IsCA:           true,
		Curve:          curve,
	}

	c, err := tbs.Sign(nil, curve, rawPriv)
	if err != nil {
		return nil, fmt.Errorf("signing CA certificate: %w", err)
	}

	certPEM, err := c.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("marshalling CA certificate to PEM: %w", err)
	}

	keyPEM := nebulaCert.MarshalSigningPrivateKeyToPEM(curve, rawPriv)

	return &CertificatePair{
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
	}, nil
}

func GenerateKeyPair() (*CertificatePair, error) {
	curve := nebulaCert.Curve_CURVE25519

	pub, rawPriv, err := newEphemeralKeypair(curve)
	if err != nil {
		return nil, err
	}

	keyPEM := nebulaCert.MarshalPrivateKeyToPEM(curve, rawPriv)

	return &CertificatePair{
		CertPEM: string(nebulaCert.MarshalPublicKeyToPEM(curve, pub)),
		KeyPEM:  string(keyPEM),
	}, nil
}

func SignCert(
	caCertPEM string,
	caKeyPEM string,
	nodeName string,
	nodeIP string,
	groupsList string,
	nodePubKeyPEM string,
) (*CertificatePair, error) {
	caCert, _, err := nebulaCert.UnmarshalCertificateFromPEM([]byte(caCertPEM))
	if err != nil {
		return nil, fmt.Errorf("parsing ca-crt: %w", err)
	}

	caKey, _, curve, err := nebulaCert.UnmarshalSigningPrivateKeyFromPEM([]byte(caKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parsing ca-key: %w", err)
	}

	if err := caCert.VerifyPrivateKey(curve, caKey); err != nil {
		return nil, fmt.Errorf("root certificate does not match private key: %w", err)
	}

	if caCert.Expired(time.Now()) {
		return nil, fmt.Errorf("ca certificate is expired")
	}

	pub, _, pubCurve, err := nebulaCert.UnmarshalPublicKeyFromPEM([]byte(nodePubKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parsing public key PEM: %w", err)
	}
	if pubCurve != curve {
		return nil, fmt.Errorf("curve of public key does not match ca curve: got %v, want %v", pubCurve, curve)
	}

	nodeIPCIDR := nodeIP
	networks, err := parseCIDRs(nodeIPCIDR)
	if err != nil {
		return nil, err
	}

	groups := []string{}
	if groupsList != "" {
		for _, g := range strings.Split(groupsList, ",") {
			groups = append(groups, strings.TrimSpace(g))
		}
	}

	duration := time.Until(caCert.NotAfter()) - time.Second*1
	notBefore := time.Now()
	notAfter := notBefore.Add(duration)

	tbs := &nebulaCert.TBSCertificate{
		Version:        nebulaCert.Version2,
		Name:           nodeName,
		Networks:       networks,
		Groups:         groups,
		UnsafeNetworks: nil,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		PublicKey:      pub,
		IsCA:           false,
		Curve:          curve,
	}

	signedCert, err := tbs.Sign(caCert, curve, caKey)
	if err != nil {
		return nil, fmt.Errorf("signing certificate: %w", err)
	}

	certPEM, err := signedCert.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("marshalling signed certificate to PEM: %w", err)
	}

	return &CertificatePair{
		CertPEM: string(certPEM),
		KeyPEM:  "",
	}, nil
}

func newSignerKeypair(curve nebulaCert.Curve) ([]byte, []byte, error) {
	switch curve {
	case nebulaCert.Curve_CURVE25519:
		pub, rawPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating ed25519 keys: %w", err)
		}
		return pub, rawPriv, nil
	case nebulaCert.Curve_P256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating ecdsa keys: %w", err)
		}
		eKey, err := key.ECDH()
		if err != nil {
			return nil, nil, fmt.Errorf("converting ecdsa key: %w", err)
		}
		return eKey.PublicKey().Bytes(), eKey.Bytes(), nil
	default:
		return nil, nil, fmt.Errorf("invalid curve: %v", curve)
	}
}

func newEphemeralKeypair(curve nebulaCert.Curve) ([]byte, []byte, error) {
	switch curve {
	case nebulaCert.Curve_CURVE25519:
		privkey := make([]byte, 32)
		if _, err := rand.Read(privkey); err != nil {
			return nil, nil, fmt.Errorf("reading random bytes: %w", err)
		}
		pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
		if err != nil {
			return nil, nil, fmt.Errorf("calculating X25519 public key: %w", err)
		}
		return pubkey, privkey, nil
	case nebulaCert.Curve_P256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating ecdsa keys: %w", err)
		}
		eKey, err := key.ECDH()
		if err != nil {
			return nil, nil, fmt.Errorf("converting ecdsa key: %w", err)
		}
		return eKey.PublicKey().Bytes(), eKey.Bytes(), nil
	default:
		return nil, nil, fmt.Errorf("invalid curve: %v", curve)
	}
}

func parseCIDRs(cidrList string) ([]netip.Prefix, error) {
	var networks []netip.Prefix
	if cidrList == "" {
		return networks, nil
	}
	for _, rs := range strings.Split(cidrList, ",") {
		rs := strings.TrimSpace(rs)
		if rs != "" {
			n, err := netip.ParsePrefix(rs)
			if err != nil {
				return nil, fmt.Errorf("invalid network definition: %s", rs)
			}
			networks = append(networks, n)
		}
	}
	return networks, nil
}
