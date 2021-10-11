package tls

import (
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

func doACME(acmeManagerTemplate certmagic.ACMEManager, zone string) (certmagic.Certificate, error) {
	configTemplate := certmagic.NewDefault()
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return configTemplate, nil
		},
	})
	config := certmagic.New(cache, *configTemplate)
	acmeManager := certmagic.NewACMEManager(config, acmeManagerTemplate)
	config.Issuers = append(config.Issuers, acmeManager)

	httpPort := fmt.Sprintf(":%d", acmeManager.AltHTTPPort)
	tlsalpnPort := fmt.Sprintf(":%d", acmeManager.AltTLSALPNPort)
	var err error
	if !acmeManager.DisableTLSALPNChallenge {
		go func() {
			_, err = tls.Listen("tcp", tlsalpnPort, config.TLSConfig())
		}()
	}
	if !acmeManager.DisableHTTPChallenge {
		go func() { err = http.ListenAndServe(httpPort, acmeManager.HTTPChallengeHandler(http.NewServeMux())) }()
	}
	cert, err := config.CacheManagedCertificate(zone)
	if err != nil {
		return certmagic.Certificate{}, err
	}
	return cert, nil
}
