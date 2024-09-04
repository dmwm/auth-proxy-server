package logging

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestCollector tests the CollectAndSend and Send functions
func TestCollector(t *testing.T) {
	// Set up a test HTTP server
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that the Authorization header is present
		auth := r.Header.Get("Authorization")
		if auth != "Basic dXNlcjpwYXNz" { // "dXNlcjpwYXNz" is "user:pass" in base64
			t.Fatalf("unexpected authorization header: %s", auth)
		}

		// Increment the request count
		atomic.AddInt32(&requestCount, 1)

		// Read the request body (which should contain JSON records)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a new collector with a max size of 3 and the test server's URL as the endpoint
	collector := NewCollector(3, server.URL, "user", "pass")

	// Create some test records
	records := []HTTPRecord{
		{Data: LogRecord{Method: "GET", API: "API1", Status: 200}},
		{Data: LogRecord{Method: "PUT", API: "API2", Status: 200}},
		{Data: LogRecord{Method: "POST", API: "API3", Status: 200}},
		{Data: LogRecord{Method: "DELETE", API: "API4", Status: 200}},
	}

	// Collect and send the records
	for _, record := range records {
		if err := collector.CollectAndSend(record); err != nil {
			t.Fatalf("failed to collect and send record: %v", err)
		}
	}

	// Ensure the remaining records are sent
	if err := collector.Send(); err != nil {
		t.Fatalf("failed to send remaining records: %v", err)
	}

	// Check the request count. It should be 2 since we sent 3 records first and 1 record second.
	expectedRequests := int32(2)
	if atomic.LoadInt32(&requestCount) != expectedRequests {
		t.Fatalf("expected %d requests to the server, but got %d", expectedRequests, requestCount)
	}
}
