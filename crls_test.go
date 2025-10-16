package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
)

// helper to make a dummy certificate
func makeDummyCert(t *testing.T) *x509.Certificate {
	serial, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
}

// makeDummyCRL writes a minimal valid CRL PEM file into dir.
func makeDummyCRL(t *testing.T, dir string) string {
	t.Helper()

	// Create a dummy CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	// Optionally include one revoked cert (for test coverage)
	revokedCert := makeDummyCert(t)
	revokedList := []pkix.RevokedCertificate{
		{
			SerialNumber:   revokedCert.SerialNumber,
			RevocationTime: time.Now().Add(-time.Hour),
		},
	}

	// Generate CRL signed by our CA
	now := time.Now()
	next := now.Add(12 * time.Hour)
	crlDER, err := caCert.CreateCRL(rand.Reader, caKey, revokedList, now, next)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	// Write PEM file to disk
	crlPath := filepath.Join(dir, "test.crl")
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	if err := os.WriteFile(crlPath, crlPEM, 0644); err != nil {
		t.Fatalf("failed to write CRL: %v", err)
	}

	return crlPath
}

// tests empty CRL directory
func TestCollectCRLFilesEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	files := collectCRLFiles([]string{tmpDir}, []string{"*.crl"})
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

// tests loading invalid CRL file
func TestLoadLocalCRLsSkipBad(t *testing.T) {
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.crl")
	if err := os.WriteFile(badFile, []byte("not a crl"), 0644); err != nil {
		t.Fatal(err)
	}

	out := loadLocalCRLs([]string{tmpDir}, []string{"*.crl"}, false)
	if len(out) != 0 {
		t.Errorf("expected 0 revoked certs, got %d", len(out))
	}
}

// tests that the CRL refresher goroutine starts and runs
func TestStartRefresher(t *testing.T) {
	tmpDir := t.TempDir()
	done := make(chan struct{})
	go func() {
		startCRLRefresher([]string{tmpDir}, []string{"*.crl"}, 100*time.Millisecond, false)
		time.Sleep(300 * time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for refresher")
	}
}

// tests VerifyPeerCertificateWithCRL behavior
func TestVerifyPeerCertificateWithCRL(t *testing.T) {
	cert := makeDummyCert(t)
	chain := [][]*x509.Certificate{{cert}}

	mockRevoked := map[string]bool{}
	revoked.Store(mockRevoked)

	// not revoked
	err := verifyPeerCertificateWithCRL(nil, chain)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// revoked
	mockRevoked[cert.SerialNumber.String()] = true
	revoked.Store(mockRevoked)
	err = verifyPeerCertificateWithCRL(nil, chain)
	if err == nil {
		t.Errorf("expected revocation error, got nil")
	}
}

// tests atomic safety of revoked map
func TestRevokedMapAtomicity(t *testing.T) {
	m := map[string]bool{"1234": true}
	revoked.Store(m)

	val := revoked.Load().(map[string]bool)
	if _, ok := val["1234"]; !ok {
		t.Error("expected to find revoked serial 1234")
	}
}

// minimal test for CRL Handler: method not allowed
func TestRefreshCRLsHandler_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/refresh-crls", nil)
	w := httptest.NewRecorder()

	RefreshCRLsHandler(w, req)
	res := w.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", res.StatusCode)
	}
}

// TestRefreshCRLsHandler_Success verifies that a valid CRL causes a successful refresh.
func TestRefreshCRLsHandler_Success(t *testing.T) {
	tmpDir := t.TempDir()
	makeDummyCRL(t, tmpDir)

	Config.CRLDirs = []string{tmpDir}
	Config.CRLGlobs = []string{"*.crl"}
	Config.CRLQuarantine = false

	req := httptest.NewRequest(http.MethodPut, "/refresh-crls", nil)
	w := httptest.NewRecorder()

	RefreshCRLsHandler(w, req)
	res := w.Result()
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unexpected result: %d %s", res.StatusCode, string(body))
	}
	if string(body) != "CRLs refreshed successfully\n" {
		t.Fatalf("unexpected body: %s", string(body))
	}
}
