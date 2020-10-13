package main

// cric module
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"log"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/dmwm/cmsauth"
)

// CricRecords list to hold CMS CRIC entries
var CricRecords cmsauth.CricRecords

// cmsRecords holds map of CricRecords for CMS users
var cmsRecords cmsauth.CricRecords

// cmsRecordsLock keeps lock for cmsRecords updates
var cmsRecordsLock sync.RWMutex

// helper function to periodically update cric records
// should be run as goroutine
func updateCricRecords() {
	var err error
	cricRecords := make(cmsauth.CricRecords)
	verbose := false
	if Config.Verbose > 2 {
		verbose = true
	}
	// if cric file is given read it first, then if we have
	// cric url we'll update it from there
	if Config.CricFile != "" {
		cricRecords, err = cmsauth.ParseCric(Config.CricFile, verbose)
		log.Printf("obtain CRIC records from %s, %v", Config.CricFile, err)
		if err != nil {
			log.Printf("Unable to update CRIC records: %v", err)
		} else {
			CricRecords = cricRecords
			keys := reflect.ValueOf(CricRecords).MapKeys()
			log.Println("Updated CRIC records", len(keys))
		}
	}
	for {
		interval := Config.UpdateCricInterval
		if interval == 0 {
			interval = 3600
		}
		// parse cric records
		if Config.CricURL != "" {
			cricRecords, err = cmsauth.GetCricData(Config.CricURL, verbose)
			log.Printf("obtain CRIC records from %s, %v", Config.CricURL, err)
		} else if Config.CricFile != "" {
			cricRecords, err = cmsauth.ParseCric(Config.CricFile, verbose)
			log.Printf("obtain CRIC records from %s, %v", Config.CricFile, err)
		} else {
			log.Println("Untable to get CRIC records no file or no url was provided")
		}
		if err != nil {
			log.Printf("Unable to update CRIC records: %v", err)
		} else {
			CricRecords = cricRecords
			keys := reflect.ValueOf(CricRecords).MapKeys()
			log.Println("Updated CRIC records", len(keys))
			updateCMSRecords(cricRecords)
			log.Println("Updated cms records", len(cmsRecords))
			if Config.Verbose > 2 {
				for k, v := range cmsRecords {
					log.Printf("cn=%s record=%+v\n", k, v)
				}
			}
		}
		d := time.Duration(interval) * time.Second
		time.Sleep(d) // sleep for next iteration
	}
}

// helper function to create cmsRecords
func updateCMSRecords(cricRecords cmsauth.CricRecords) {
	cmsRecordsLock.Lock()
	defer cmsRecordsLock.Unlock()
	cmsRecords = make(cmsauth.CricRecords)
	for _, r := range cricRecords {
		for _, dn := range r.DNs {
			for _, v := range strings.Split(dn, "/") {
				if strings.HasPrefix(v, "CN=") {
					cmsRecords[v] = r
				}
			}
		}
	}
}
