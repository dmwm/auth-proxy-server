package cric

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/dmwm/cmsauth"
)

// global variables for our test
var verbose bool
var dn string

// Roles structure describes user roles in CRIC
type Roles struct {
	User []string `json:"user"`
}

// CricRecord structure describes cric records
type CricRecord struct {
	DN    string `json:"DN"`
	EMAIL string `json:"EMAIL"`
	ID    int    `json:"ID"`
	NAME  string `json:"NAME"`
	ROLES Roles
}

func genCricRecords() string {
	var records []CricRecord
	for n := 0; n < 5000; n++ {
		dn = fmt.Sprintf("/DC=%d/OU=%d/CN=%d", n, n, n)
		email := fmt.Sprintf("email-%d@mail.com", n)
		name := fmt.Sprintf("name-%d", n)
		rec := CricRecord{DN: dn, EMAIL: email, ID: n, NAME: name}
		records = append(records, rec)
	}
	// Create a temporary file
	tmpFile, err := ioutil.TempFile("", "cric*.json")
	if err != nil {
		log.Fatal(err)
	}
	defer tmpFile.Close()

	fmt.Println("Temporary file created:", tmpFile.Name())
	fmt.Println("last dn", dn)
	tmpFile.Write([]byte("[\n"))

	// Write JSON records to the temporary file
	for idx, record := range records {
		jsonData, err := json.Marshal(record)
		if err != nil {
			log.Fatal(err)
		}

		_, err = tmpFile.Write(jsonData)
		if err != nil {
			log.Fatal(err)
		}

		// Write a newline to separate JSON objects
		msg := ",\n"
		if idx == len(records)-1 {
			msg = "\n"
		}
		_, err = tmpFile.Write([]byte(msg))
		if err != nil {
			log.Fatal(err)
		}
	}
	tmpFile.Write([]byte("]\n"))
	return tmpFile.Name()
}

// TestCricRecords provides test for cric records
func TestCricRecords(t *testing.T) {
	cricFile := genCricRecords()
	defer func(fname string) {
		err := os.Remove(fname)
		if err != nil {
			t.Fatal(err)
		}
	}(cricFile)

	cricRecords, err := cmsauth.ParseCric(cricFile, verbose)
	fmt.Printf("Load %d cric records\n", len(cricRecords))
	if err != nil {
		t.Fatal(err)
	}
	CricRecords = cricRecords
	UpdateCMSRecords(cricRecords)
	rec, err := FindUser(dn)
	if err != nil {
		t.Fatal(err)
	}
	if rec.DN != dn {
		t.Fatal("no user found, cric record", rec)
	}
	fmt.Printf("found %+v\n", rec)
}

// BenchmarkCricRecords provides test of GET method for our service
func BenchmarkCricRecords(b *testing.B) {
	cricFile := genCricRecords()
	defer func(fname string) {
		err := os.Remove(fname)
		if err != nil {
			b.Fatal(err)
		}
	}(cricFile)

	// perform benchmark test
	for n := 0; n < b.N; n++ {
		cricRecords, err := cmsauth.ParseCric(cricFile, verbose)
		if err != nil {
			b.Fatal(err)
		}
		CricRecords = cricRecords
		UpdateCMSRecords(cricRecords)
		rec, err := FindUser(dn)
		if err != nil {
			b.Fatal(err)
		}
		if rec.DN != dn {
			b.Fatal("no user found, cric record", rec)
		}
	}
}
