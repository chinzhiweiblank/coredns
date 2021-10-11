package tls

import (
	ctls "crypto/tls"
	"strconv"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/tls"
)

func init() { plugin.Register("tls", setup) }

func setup(c *caddy.Controller) error {
	err := parseTLS(c)
	if err != nil {
		return plugin.Error("tls", err)
	}
	return nil
}

func setTLSDefaults(tls *ctls.Config) {
	tls.MinVersion = ctls.VersionTLS12
	tls.MaxVersion = ctls.VersionTLS13
	tls.CipherSuites = []uint16{
		ctls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		ctls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ctls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		ctls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		ctls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		ctls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ctls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		ctls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ctls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
	tls.PreferServerCipherSuites = true
}

func parseTLS(c *caddy.Controller) error {
	config := dnsserver.GetConfig(c)

	if config.TLSConfig != nil {
		return plugin.Error("tls", c.Errf("TLS already configured for this server instance"))
	}

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) < 2 || len(args) > 3 {
			return plugin.Error("tls", c.ArgErr())
		}
		clientAuth := ctls.NoClientCert
		for c.NextBlock() {
			switch c.Val() {
			case "client_auth":
				authTypeArgs := c.RemainingArgs()
				if len(authTypeArgs) != 1 {
					return c.ArgErr()
				}
				switch authTypeArgs[0] {
				case "nocert":
					clientAuth = ctls.NoClientCert
				case "request":
					clientAuth = ctls.RequestClientCert
				case "require":
					clientAuth = ctls.RequireAnyClientCert
				case "verify_if_given":
					clientAuth = ctls.VerifyClientCertIfGiven
				case "require_and_verify":
					clientAuth = ctls.RequireAndVerifyClientCert
				default:
					return c.Errf("unknown authentication type '%s'", authTypeArgs[0])
				}
			default:
				return c.Errf("unknown option '%s'", c.Val())
			}
		}
		tls, err := tls.NewTLSConfigFromArgs(args...)
		if err != nil {
			return err
		}
		tls.ClientAuth = clientAuth
		// NewTLSConfigFromArgs only sets RootCAs, so we need to let ClientCAs refer to it.
		tls.ClientCAs = tls.RootCAs

		setTLSDefaults(tls)

		config.TLSConfig = tls
	}
	return nil
}

func parseAcme(c *caddy.Controller) error {
	var zone string
	for c.NextBlock() {
		switch c.Val() {
		case "acme":
			for c.Next() {
				for c.NextBlock() {
					term := strings.ToLower(c.Val())
					var acmeTemplate certmagic.ACMEManager
					switch term {
					case CHALLENGE:
						args := c.RemainingArgs()
						challenge := args[0]
						if !(len(args) == 3 && args[1] == PORT) {
							return c.Errf("unexpected number of arguments: %#v", args)
						}
						port, err := strconv.Atoi(args[2])
						if err != nil {
							return c.Errf("%s port is not an int: %#v", challenge, args)
						}
						switch challenge {
						case HTTPChallenge:
							acmeTemplate.AltHTTPPort = port
							acmeTemplate.DisableHTTPChallenge = false
						case TLPSALPNChallenge:
							acmeTemplate.AltTLSALPNPort = port
							acmeTemplate.DisableTLSALPNChallenge = false
						default:
							return c.Errf("unexpected challenge %s: challenge should only be tlsalpn or http", challenge)
						}
					default:
						return c.Errf("unexpected term: %s: term should only be challenge or domain", term)
					}
					_, err := doACME(acmeTemplate, zone)
					if err != nil {
						return c.Errf("unexpected term: %s: term should only be challenge or domain", term)
					}
				}
			}
		default:
			return c.Errf("unknown option '%s'", c.Val())
		}
	}
	return nil
}
