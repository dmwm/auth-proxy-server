package main

import (
	"log"
	"testing"

	"github.com/dmwm/cmsauth"
	"github.com/stretchr/testify/assert"
)

// Test_checkFile function
func Test_checkFile(t *testing.T) {
	fname := "/etc/hosts"
	res := checkFile(fname)
	assert.Equal(t, res, fname)
}

// Test findCN function
func Test_findCN(t *testing.T) {
	subject := "CN=First Last OU=Organic Units+OU=Users"
	cn, err := findCN(subject)
	assert.Equal(t, err, nil)
	assert.Equal(t, cn, "CN=First Last")
	subject = "O=IT CN=First Last OU=Organic Units+OU=Users"
	cn, err = findCN(subject)
	assert.Equal(t, err, nil)
	assert.Equal(t, cn, "CN=First Last")
}

// Test fundUser function
func Test_findUser(t *testing.T) {
	CricRecords = make(cmsauth.CricRecords)
	cmsRecords = make(cmsauth.CricRecords)
	var dns []string
	dn1 := "/DC=org/DC=dc/DC=tcs/C=country/O=Institute Test/CN=First Last"
	dn2 := "/DC=org/DC=dc/DC=tcs/C=country/O=Institute Test/CN=First Last name@email.com"
	dns = append(dns, dn1)
	dns = append(dns, dn2)
	rec := cmsauth.CricEntry{Login: "name", DNs: dns}
	CricRecords["name"] = rec
	updateCMSRecords(CricRecords)
	var subjects []string
	s := "CN=First Last"
	subjects = append(subjects, s)
	_, err := findUser(subjects)
	assert.Equal(t, err, nil)
}

// Benchmark findUser function
func Benchmark_findUser(b *testing.B) {
	CricRecords = make(cmsauth.CricRecords)
	cmsRecords = make(cmsauth.CricRecords)
	rec := cmsauth.CricEntry{DN: "/DC=org/DC=dc/DC=tcs/C=country/O=Institute Test/CN=First Last"}
	CricRecords["login"] = rec
	updateCMSRecords(CricRecords)
	var subjects []string
	s := "CN=First Last"
	subjects = append(subjects, s)
	for n := 0; n < b.N; n++ {
		_, err := findUser(subjects)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// Test_InList function
func Test_InList(t *testing.T) {
	list := []string{"a", "b"}
	res := InList("a", list)
	assert.Equal(t, res, true)
	res = InList("c", list)
	assert.Equal(t, res, false)
}
