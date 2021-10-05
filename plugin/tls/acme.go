package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/caddyserver/certmagic"
)

const (
	HTTPChallenge     = "http"
	TLPSALPNChallenge = "tlsalpn"
	CHALLENGE         = "challenge"
	PORT              = "port"
)

type ACME struct {
	Config *certmagic.Config
	Zone   string
}

func NewACME(acmeManagerTemplate certmagic.ACMEManager, zone string) ACME {
	configTemplate := certmagic.NewDefault()
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return configTemplate, nil
		},
	})
	config := certmagic.New(cache, *configTemplate)
	acmeManager := certmagic.NewACMEManager(config, acmeManagerTemplate)
	config.Issuers = append(config.Issuers, acmeManager)
	return ACME{
		Config: config,
		Zone:   zone,
	}
}

func (a ACME) OnStartup() error {
	acmeManager := a.Config.Issuers[0].(*certmagic.ACMEManager)
	httpPort := fmt.Sprintf(":%d", acmeManager.AltHTTPPort)
	tlsalpnPort := fmt.Sprintf(":%d", acmeManager.AltTLSALPNPort)
	tlsConfig := a.Config.TLSConfig()
	var err error
	if !acmeManager.DisableTLSALPNChallenge {
		go func() {
			_, err = tls.Listen("tcp", tlsalpnPort, tlsConfig)
		}()
	}
	if !acmeManager.DisableHTTPChallenge {
		go func() { err = http.ListenAndServe(httpPort, acmeManager.HTTPChallengeHandler(http.NewServeMux())) }()
	}
	return err
}

func (a ACME) IssueCert(ctx context.Context, zones []string) error {
	err := a.Config.ManageAsync(ctx, zones)
	return err
}

func (a ACME) GetCert(zone string) error {
	err := a.Config.ObtainCertAsync(context.Background(), zone)
	return err
}
