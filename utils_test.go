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
