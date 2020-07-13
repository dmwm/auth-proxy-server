package main

// cric module
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"log"
	"reflect"
	"time"

	"github.com/dmwm/cmsauth"
)

// CricRecords list to hold CMS CRIC entries
var CricRecords cmsauth.CricRecords

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
		if Config.CricUrl != "" {
			cricRecords, err = cmsauth.GetCricData(Config.CricUrl, verbose)
			log.Printf("obtain CRIC records from %s, %v", Config.CricUrl, err)
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
		}
		d := time.Duration(interval) * time.Second
		time.Sleep(d) // sleep for next iteration
	}
}
