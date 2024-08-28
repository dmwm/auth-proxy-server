package cric

// cric module
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/dmwm/cmsauth"
)

// CricRecords list to hold CMS CRIC entries
var CricRecords cmsauth.CricRecords

// cmsRecords holds map of CricRecords for CMS users
var cmsRecords cmsauth.CricRecords

// mutex keeps lock for cmsRecords updates
var mutex sync.RWMutex

// int pattern
var intPattern = regexp.MustCompile(`^\d+$`)

// helper function to update cric records
func updateCricRecords(key, cricFile, cricURL string, verbose bool) {
	cricRecords := make(cmsauth.CricRecords)
	var err error
	// use cricFile first if it exists, otherwise use cricURL if it is given
	if _, e := os.Stat(cricFile); e == nil {
		if key == "id" {
			cricRecords, err = cmsauth.ParseCricByKey(cricFile, "id", verbose)
		} else {
			cricRecords, err = cmsauth.ParseCric(cricFile, verbose)
		}
		log.Printf("obtain CRIC records from %s using key %s, error %v", cricFile, key, err)
	} else if cricURL != "" {
		if key == "id" {
			cricRecords, err = cmsauth.GetCricDataByKey(cricURL, "id", verbose)
		} else {
			cricRecords, err = cmsauth.GetCricData(cricURL, verbose)
		}
		log.Printf("obtain CRIC records from %s using key %s, error %v", cricURL, key, err)
	} else {
		log.Println("Unable to get CRIC records no file or no url was provided")
	}
	if err != nil {
		log.Printf("Unable to update CRIC records: %v", err)
	} else {
		CricRecords = cricRecords
		keys := reflect.ValueOf(CricRecords).MapKeys()
		log.Println("Updated CRIC records", len(keys))
		if key == "id" {
			cmsRecords = cricRecords
		} else {
			UpdateCMSRecords(cricRecords)
		}
	}
}

// UpdateCricRecords periodically updates cric records
// should be run as goroutine
func UpdateCricRecords(key, cricFile, cricURL string, cricUpdateInterval int64, cricVerbose int) {
	log.Println("update cric records with", key, "as a key")
	verbose := false
	if cricVerbose > 0 {
		verbose = true
	}
	iter := 0
	for {
		interval := cricUpdateInterval
		if interval == 0 {
			interval = 3600
		}
		updateCricRecords(key, cricFile, cricURL, verbose)
		log.Println("Updated cms records", len(cmsRecords))
		if cricVerbose > 2 {
			for k, v := range cmsRecords {
				log.Printf("key=%s value=%s record=%+v\n", key, k, v)
			}
		} else if cricVerbose > 0 {
			for k, v := range cmsRecords {
				log.Printf("key=%s value=%s record=%+v\n", key, k, v)
				break // break to avoid lots of CRIC record printous
			}
		}
		d := time.Duration(interval) * time.Second
		time.Sleep(d) // sleep for next iteration
		iter += 1
	}
}

// UpdateCMSRecords updates CMS Records
func UpdateCMSRecords(cricRecords cmsauth.CricRecords) {
	cmsRecords = make(cmsauth.CricRecords)
	for _, r := range cricRecords {
		for _, dn := range r.DNs {
			sortedDN := cmsauth.GetSortedDN(dn)
			mutex.Lock()
			cmsRecords[sortedDN] = r
			mutex.Unlock()
		}
	}
}

// FindUser finds user info in cric records for given DN
func FindUser(dn string) (cmsauth.CricEntry, error) {
	sortedDN := cmsauth.GetSortedDN(dn)
	mutex.RLock()
	r, ok := cmsRecords[sortedDN]
	mutex.RUnlock()
	if ok {
		return r, nil
	}
	msg := fmt.Sprintf("user not found: %v\n", sortedDN)
	return cmsauth.CricEntry{}, errors.New(msg)
}
