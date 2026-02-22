package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/samirkhoja/agent-proxy/internal/util"
)

type CertificateAuthority struct {
	Cert       *x509.Certificate
	Key        *ecdsa.PrivateKey
	CertDER    []byte
	TLSCert    tls.Certificate
	CertPath   string
	KeyPath    string
	CertSHA256 string
}

func SetupCA(dir, commonName string, overwrite bool) (*CertificateAuthority, error) {
	if commonName == "" {
		commonName = "agentproxy Local CA"
	}
	certPath := filepath.Join(dir, "ca_cert.pem")
	keyPath := filepath.Join(dir, "ca_key.pem")

	if !overwrite {
		if _, err := os.Stat(certPath); err == nil {
			if _, errKey := os.Stat(keyPath); errKey == nil {
				return LoadCA(certPath, keyPath)
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"agentproxy"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create ca cert: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ca private key: %w", err)
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyBytes, 0o600); err != nil {
		return nil, err
	}
	return LoadCA(certPath, keyPath)
}

func LoadCA(certPath, keyPath string) (*CertificateAuthority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	if err := tightenPrivateKeyPermissions(keyPath); err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("invalid ca cert pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid ca key pem")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load ca key pair: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return &CertificateAuthority{
		Cert:       cert,
		Key:        key,
		CertDER:    cert.Raw,
		TLSCert:    tlsCert,
		CertPath:   certPath,
		KeyPath:    keyPath,
		CertSHA256: strings.ToUpper(hex.EncodeToString(sum[:])),
	}, nil
}

type RotateResult struct {
	ArchivedCertPath string
	ArchivedKeyPath  string
	NewCA            *CertificateAuthority
}

func RotateCA(dir, commonName string) (RotateResult, error) {
	if commonName == "" {
		commonName = "agentproxy Local CA"
	}
	if err := os.MkdirAll(util.RevokedCADir(dir), 0o700); err != nil {
		return RotateResult{}, fmt.Errorf("create revoked dir: %w", err)
	}

	certPath := util.CACertPath(dir)
	keyPath := util.CAKeyPath(dir)
	ts := time.Now().UTC().Format("20060102-150405")

	var archivedCertPath string
	if _, err := os.Stat(certPath); err == nil {
		// Keep a dated backup so trust can be audited/rolled back during rotation.
		archivedCertPath = filepath.Join(util.RevokedCADir(dir), "ca_cert_"+ts+".pem")
		if err := copyFile(certPath, archivedCertPath, 0o644); err != nil {
			return RotateResult{}, fmt.Errorf("archive old cert: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return RotateResult{}, fmt.Errorf("stat old cert: %w", err)
	}

	var archivedKeyPath string
	if _, err := os.Stat(keyPath); err == nil {
		archivedKeyPath = filepath.Join(util.RevokedCADir(dir), "ca_key_"+ts+".pem")
		if err := copyFile(keyPath, archivedKeyPath, 0o600); err != nil {
			return RotateResult{}, fmt.Errorf("archive old key: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return RotateResult{}, fmt.Errorf("stat old key: %w", err)
	}

	newCA, err := SetupCA(dir, commonName, true)
	if err != nil {
		return RotateResult{}, err
	}
	return RotateResult{
		ArchivedCertPath: archivedCertPath,
		ArchivedKeyPath:  archivedKeyPath,
		NewCA:            newCA,
	}, nil
}

type RevokeResult struct {
	RevokedCertPath string
	RevokedKeyPath  string
}

func RevokeCA(dir string) (RevokeResult, error) {
	revokedDir := util.RevokedCADir(dir)
	if err := os.MkdirAll(revokedDir, 0o700); err != nil {
		return RevokeResult{}, fmt.Errorf("create revoked dir: %w", err)
	}

	certPath := util.CACertPath(dir)
	keyPath := util.CAKeyPath(dir)
	ts := time.Now().UTC().Format("20060102-150405")
	result := RevokeResult{}

	if _, err := os.Stat(certPath); err == nil {
		dst := filepath.Join(revokedDir, "revoked_ca_cert_"+ts+".pem")
		if err := os.Rename(certPath, dst); err != nil {
			return RevokeResult{}, fmt.Errorf("revoke cert: %w", err)
		}
		result.RevokedCertPath = dst
	} else if !errors.Is(err, os.ErrNotExist) {
		return RevokeResult{}, fmt.Errorf("stat cert: %w", err)
	}
	if _, err := os.Stat(keyPath); err == nil {
		dst := filepath.Join(revokedDir, "revoked_ca_key_"+ts+".pem")
		if err := os.Rename(keyPath, dst); err != nil {
			return RevokeResult{}, fmt.Errorf("revoke key: %w", err)
		}
		result.RevokedKeyPath = dst
	} else if !errors.Is(err, os.ErrNotExist) {
		return RevokeResult{}, fmt.Errorf("stat key: %w", err)
	}
	if result.RevokedCertPath == "" && result.RevokedKeyPath == "" {
		return RevokeResult{}, errors.New("no active CA cert/key found")
	}
	return result, nil
}

type CertCache struct {
	ca    *CertificateAuthority
	mu    sync.Mutex
	certs map[string]*tls.Certificate
}

func NewCertCache(ca *CertificateAuthority) *CertCache {
	return &CertCache{
		ca:    ca,
		certs: map[string]*tls.Certificate{},
	}
}

func (c *CertCache) CertForHost(hostport string) (*tls.Certificate, error) {
	host := canonicalHost(hostport)
	if host == "" {
		return nil, errors.New("empty host")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if cert, ok := c.certs[host]; ok {
		return cert, nil
	}

	// Mint and cache per-host leaf certs to avoid generating on every request.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   now.Add(-1 * time.Hour),
		NotAfter:    now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.DNSNames = nil
		tpl.IPAddresses = []net.IP{ip}
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, c.ca.Cert, &leafKey.PublicKey, c.ca.Key)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}
	leafKeyBytes, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, fmt.Errorf("marshal leaf key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.ca.CertDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyBytes})
	pair, err := tls.X509KeyPair(append(certPEM, caPEM...), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load leaf key pair: %w", err)
	}
	c.certs[host] = &pair
	return &pair, nil
}

func canonicalHost(hostport string) string {
	host := strings.TrimSpace(hostport)
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			return strings.Trim(h, "[]")
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	if strings.Contains(host, ":") {
		return strings.Trim(host, "[]")
	}
	return host
}

func randomSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	return serial, nil
}

func writePEM(path, typ string, bytes []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: bytes}); err != nil {
		return fmt.Errorf("write pem %s: %w", path, err)
	}
	return nil
}

func tightenPrivateKeyPermissions(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat key file: %w", err)
	}
	perm := st.Mode().Perm()
	if perm == 0o600 {
		return nil
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("enforce key mode 0600: %w", err)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
