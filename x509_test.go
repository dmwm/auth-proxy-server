package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestX509RequestHandler provides test of GET method for our service
func TestX509RequestHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(x509RequestHandler)
	handler.ServeHTTP(rr, req)

	// since we don't provide valid cert we should get http.StatusUnauthorized
	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}
