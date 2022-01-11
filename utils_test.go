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

	rurl = "/path/a/b/c/d?123"
	path = "/path"
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

	rurl = "/ms-unmerged/bla"
	path = "/ms-unmerged/"
	result = PathMatched(rurl, path, false)
	assert.Equal(t, result, true)

	// strict rule should match path exactly
	rurl = "/ms-unmerged/bla&rse=t1"
	path = "/ms-unmerged/"
	result = PathMatched(rurl, path, true)
	assert.Equal(t, result, false)

	// with loose strict rule the provided rurl can match the path
	rurl = "/ms-unmerged/bla&rse=t1"
	path = "/ms-unmerged/"
	result = PathMatched(rurl, path, false)
	assert.Equal(t, result, true)

	rurl = "/ms-unmerged/bla&rse=t1"
	path = "/ms-unmerged/.*rse=t1"
	result = PathMatched(rurl, path, false)
	assert.Equal(t, result, true)

	rurl = "/ms-unmerged/bla&rse=t1&foo=1"
	path = "/ms-unmerged/.*rse=t1"
	result = PathMatched(rurl, path, false)
	assert.Equal(t, result, true)

	// but we can't match rurl with strict rule
	rurl = "/ms-unmerged/bla&rse=t1&foo=1"
	path = "/ms-unmerged/.*rse=t1"
	result = PathMatched(rurl, path, true)
	assert.Equal(t, result, false)

	rurl = "/ms-unmerged/bla&rse=t2"
	path = "/ms-unmerged/.*rse=t1"
	result = PathMatched(rurl, path, false)
	assert.Equal(t, result, false)
}

// Test_RedirectRules test RedirectRules API
func Test_RedirectRules(t *testing.T) {
	var ingressRules []Ingress
	ingressRules = append(ingressRules, Ingress{Path: "/path/aaa"})
	ingressRules = append(ingressRules, Ingress{Path: "/path/"})
	ingressRules = append(ingressRules, Ingress{Path: "/path/rse"})
	rmap, rules := RedirectRules(ingressRules)
	expect := []string{"/path/rse", "/path/aaa", "/path/"}
	assert.Equal(t, rules, expect)
	assert.Equal(t, len(rmap), len(rules))
}
