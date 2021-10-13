package tls

import (
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
	cert, err := config.CacheManagedCertificate(zone)
	if err != nil {
		return certmagic.Certificate{}, err
	}
	return cert, nil
}
