package main

import (
	"testing"

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

// Test_InList function
func Test_InList(t *testing.T) {
	list := []string{"a", "b"}
	res := InList("a", list)
	assert.Equal(t, res, true)
	res = InList("c", list)
	assert.Equal(t, res, false)
}

// Test_PathMatched function
func Test_PathMatched(t *testing.T) {
	// check path prefix matching
	rurl := "/couchdb/workqueue"
	path := "/couchdb"
	result := PathMatched(rurl, path, false)
	assert.Equal(t, result, true)

	rurl = "/dbs/int/global/DBSReader/datasets?dataset=/aaa/bbb/ccc"
	path = "/dbs/int/global/DBSReader"
	result = PathMatched(rurl, path, false)
	assert.Equal(t, result, true)

	// check strict path matching
	rurl = "/couchdb/workqueue"
	path = "/couchdb"
	result = PathMatched(rurl, path, true)
	assert.Equal(t, result, true)

	rurl = "/couchdb/workqueue?q=123"
	path = "/couchdb"
	result = PathMatched(rurl, path, true)
	assert.Equal(t, result, true)

	rurl = "/couchdb/workqueue/params"
	path = "/couchdb"
	result = PathMatched(rurl, path, true)
	assert.Equal(t, result, false)
}
