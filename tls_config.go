package openconnect

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/youmark/pkcs8"
)

type mcaIdentity struct {
	Certificate [][]byte
	Signer      crypto.Signer
}

func buildClientTLS(options ClientOptions) (*tls.Config, *mcaIdentity, error) {
	tlsOptions := options.TLSConfig
	for name, material := range map[string]Material{
		"certificate authority": tlsOptions.CertificateAuthority,
		"client certificate":    tlsOptions.Certificate,
		"client key":            tlsOptions.Key,
		"MCA certificate":       tlsOptions.MCACertificate,
		"MCA key":               tlsOptions.MCAKey,
	} {
		err := material.Validate(name)
		if err != nil {
			return nil, nil, err
		}
	}
	configuration := &tls.Config{}
	if tlsOptions.Config != nil {
		configuration = cloneTLSConfig(tlsOptions.Config)
	}
	if tlsOptions.CertificateAuthority.IsSet() {
		certificateAuthority, err := loadMaterial(tlsOptions.CertificateAuthority)
		if err != nil {
			return nil, nil, E.Cause(err, "load TLS certificate authority")
		}
		rootCAs := configuration.RootCAs
		if rootCAs == nil {
			rootCAs, err = x509.SystemCertPool()
			if err != nil {
				return nil, nil, E.Cause(err, "load system certificate authorities")
			}
		} else {
			rootCAs = rootCAs.Clone()
		}
		if !rootCAs.AppendCertsFromPEM(certificateAuthority) {
			return nil, nil, E.Extend(ErrInvalidTLSMaterial, "certificate authority")
		}
		configuration.RootCAs = rootCAs
	}
	clientCertificate, err := loadOptionalCertificate(tlsOptions.Certificate, tlsOptions.Key, tlsOptions.KeyPassword, "client")
	if err != nil {
		return nil, nil, err
	}
	if clientCertificate != nil {
		configuration.Certificates = append(configuration.Certificates, *clientCertificate)
	}
	mcaCertificate, err := loadOptionalCertificate(tlsOptions.MCACertificate, tlsOptions.MCAKey, tlsOptions.MCAKeyPassword, "MCA")
	if err != nil {
		return nil, nil, err
	}
	var identity *mcaIdentity
	if mcaCertificate != nil {
		signer, isSigner := mcaCertificate.PrivateKey.(crypto.Signer)
		if !isSigner {
			return nil, nil, E.Extend(ErrInvalidTLSMaterial, "MCA private key is not a signer")
		}
		identity = &mcaIdentity{
			Certificate: cloneByteSlices(mcaCertificate.Certificate),
			Signer:      signer,
		}
	}
	if options.AllowInsecureCrypto {
		if configuration.MinVersion == 0 {
			configuration.MinVersion = tls.VersionTLS10
		}
		if len(configuration.CipherSuites) == 0 {
			configuration.CipherSuites = insecureOptInCipherSuites()
		}
	} else {
		if configuration.MinVersion != 0 && configuration.MinVersion < tls.VersionTLS12 ||
			configuration.MaxVersion != 0 && configuration.MaxVersion < tls.VersionTLS12 {
			return nil, nil, ErrDeprecatedCryptoDisabled
		}
		insecureCipherSuites := make(map[uint16]struct{})
		for _, cipherSuite := range tls.InsecureCipherSuites() {
			insecureCipherSuites[cipherSuite.ID] = struct{}{}
		}
		for _, cipherSuite := range configuration.CipherSuites {
			_, insecure := insecureCipherSuites[cipherSuite]
			if insecure {
				return nil, nil, ErrDeprecatedCryptoDisabled
			}
		}
	}
	return configuration, identity, nil
}

func cloneTLSConfig(configuration *tls.Config) *tls.Config {
	cloned := configuration.Clone()
	cloned.Certificates = cloneTLSCertificates(cloned.Certificates)
	cloned.CipherSuites = append([]uint16(nil), cloned.CipherSuites...)
	cloned.CurvePreferences = append([]tls.CurveID(nil), cloned.CurvePreferences...)
	cloned.NextProtos = append([]string(nil), cloned.NextProtos...)
	cloned.EncryptedClientHelloConfigList = append([]byte(nil), cloned.EncryptedClientHelloConfigList...)
	if cloned.RootCAs != nil {
		cloned.RootCAs = cloned.RootCAs.Clone()
	}
	return cloned
}

// Go crypto/tls (*Conn).getClientCertificate calls GetClientCertificate when configured; otherwise it selects the first configured chain accepted by CertificateRequestInfo.SupportsCertificate and returns an empty certificate when none match.
func wrapTLSClientCertificateSelection(configuration *tls.Config, record func(certificate *tls.Certificate)) {
	configuredCallback := configuration.GetClientCertificate
	configuredCertificates := configuration.Certificates
	configuration.GetClientCertificate = func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		var selectedCertificate *tls.Certificate
		var err error
		if configuredCallback != nil {
			selectedCertificate, err = configuredCallback(request)
		} else {
			for _, configuredCertificate := range configuredCertificates {
				supportErr := request.SupportsCertificate(&configuredCertificate)
				if supportErr != nil {
					continue
				}
				selectedCertificate = &configuredCertificate
				break
			}
			if selectedCertificate == nil {
				selectedCertificate = new(tls.Certificate)
			}
		}
		if err == nil {
			record(selectedCertificate)
		}
		return selectedCertificate, err
	}
}

func loadOptionalCertificate(certificateMaterial Material, keyMaterial Material, password string, name string) (*tls.Certificate, error) {
	if certificateMaterial.IsSet() != keyMaterial.IsSet() {
		return nil, E.Extend(ErrInvalidTLSMaterial, name, " certificate and key must both be set")
	}
	if !certificateMaterial.IsSet() {
		return nil, nil
	}
	certificatePEM, err := loadMaterial(certificateMaterial)
	if err != nil {
		return nil, E.Cause(err, "load ", name, " certificate")
	}
	keyPEM, err := loadMaterial(keyMaterial)
	if err != nil {
		return nil, E.Cause(err, "load ", name, " key")
	}
	keyPEM, err = decryptPrivateKeyPEM(keyPEM, password)
	if err != nil {
		return nil, E.Cause(err, "decrypt ", name, " key")
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, E.Cause(err, "parse ", name, " certificate and key")
	}
	return &certificate, nil
}

func decryptPrivateKeyPEM(content []byte, password string) ([]byte, error) {
	rest := content
	result := make([]byte, 0, len(content))
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			if len(result) == 0 {
				return content, nil
			}
			result = append(result, rest...)
			break
		}
		rest = remaining
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			if password == "" {
				return nil, E.New("encrypted PKCS#8 private key requires a password")
			}
			privateKey, err := parseEncryptedPKCS8PrivateKey(block.Bytes, password)
			if err != nil {
				return nil, E.Cause(err, "decrypt PKCS#8 private key")
			}
			decrypted, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				return nil, E.Cause(err, "marshal decrypted PKCS#8 private key")
			}
			block.Type = "PRIVATE KEY"
			block.Bytes = decrypted
			block.Headers = nil
		}
		// Go crypto/x509 exposes RFC 1423 PEM decryption for legacy gateway client keys only through this deprecated API.
		//nolint:staticcheck
		if x509.IsEncryptedPEMBlock(block) {
			if password == "" {
				return nil, E.New("encrypted private key requires a password")
			}
			// Go crypto/x509 exposes RFC 1423 PEM decryption for legacy gateway client keys only through this deprecated API.
			//nolint:staticcheck
			decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
			if err != nil {
				return nil, err
			}
			block.Bytes = decrypted
			block.Headers = nil
		}
		result = append(result, pem.EncodeToMemory(block)...)
	}
	return result, nil
}

func parseEncryptedPKCS8PrivateKey(content []byte, password string) (privateKey any, err error) {
	defer func() {
		panicValue := recover()
		if panicValue != nil {
			privateKey = nil
			err = E.New("invalid encrypted PKCS#8 private key: ", panicValue)
		}
	}()
	privateKey, err = pkcs8.ParsePKCS8PrivateKey(content, []byte(password))
	return
}

func insecureOptInCipherSuites() []uint16 {
	cipherSuites := tls.CipherSuites()
	result := make([]uint16, 0, len(cipherSuites)+6)
	for _, cipherSuite := range cipherSuites {
		for _, version := range cipherSuite.SupportedVersions {
			if version <= tls.VersionTLS12 {
				result = append(result, cipherSuite.ID)
				break
			}
		}
	}
	result = append(result,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	)
	return result
}

func cloneTLSCertificates(certificates []tls.Certificate) []tls.Certificate {
	cloned := make([]tls.Certificate, len(certificates))
	for i := range certificates {
		cloned[i] = certificates[i]
		cloned[i].Certificate = cloneByteSlices(certificates[i].Certificate)
		cloned[i].SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), certificates[i].SupportedSignatureAlgorithms...)
		cloned[i].OCSPStaple = append([]byte(nil), certificates[i].OCSPStaple...)
		cloned[i].SignedCertificateTimestamps = cloneByteSlices(certificates[i].SignedCertificateTimestamps)
		cloned[i].Leaf = nil
	}
	return cloned
}

func cloneByteSlices(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for i := range values {
		cloned[i] = append([]byte(nil), values[i]...)
	}
	return cloned
}
