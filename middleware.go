package main

import (
	"net/http"
)

// helper middleware to cross-check user's certificate via VerifyPeerCertificate
// function and yield back to users trouble page
func certMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			authTroubleHandler(w, r)
			return
		}

		// Convert back to [][]byte for compatibility with VerifyPeerCertificate
		var certBytes [][]byte
		for _, c := range r.TLS.PeerCertificates {
			certBytes = append(certBytes, c.Raw)
		}

		if err := VerifyPeerCertificate(certBytes, nil); err != nil {
			authTroubleHandler(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}
