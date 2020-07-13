package main

// stomp module provides StompAMQ integration which allow
// to yield request logs directly to StompAMQ end-point
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"errors"
	"fmt"
	"log"

	"github.com/go-stomp/stomp"
)

// global pointer to Stomp connection
var stompConn *stomp.Conn

// StompConnection returns Stomp connection
func StompConnection() (*stomp.Conn, error) {
	if Config.StompConfig.URI == "" {
		err := errors.New("Unable to connect to Stomp, no URI")
		return nil, err
	}
	if Config.StompConfig.Login == "" {
		err := errors.New("Unable to connect to Stomp, no login")
		return nil, err
	}
	if Config.StompConfig.Password == "" {
		err := errors.New("Unable to connect to Stomp, no password")
		return nil, err
	}
	conn, err := stomp.Dial("tcp",
		Config.StompConfig.URI,
		stomp.ConnOpt.Login(Config.StompConfig.Login, Config.StompConfig.Password))
	if err != nil {
		err := errors.New(fmt.Sprintf("Unable to connect to %s, error %v", Config.StompConfig.URI, err))
		return nil, err
	}
	if Config.StompConfig.Verbose {
		log.Printf("connected to StompAMQ server %s %v", Config.StompConfig.URI, conn)
	}
	return conn, err
}

// helper function to send dat to StompAMQ end-point
func sendToStomp(data []byte) {
	var err error
	stompConn, err = StompConnection()
	// defer stomp connection if it exists
	if stompConn != nil {
		defer stompConn.Disconnect()
	}
	if err != nil {
		log.Println(err)
		return
	}
	contentType := "application/json"
	nIter := 3 // default
	if Config.StompConfig.Iterations > 0 {
		nIter = Config.StompConfig.Iterations
	}
	for i := 0; i < nIter; i++ {
		err := stompConn.Send(Config.StompConfig.Endpoint, contentType, data)
		if err != nil {
			if i == Config.StompConfig.Iterations-1 {
				log.Printf("unable to send data to %s, data %s, error %v, iteration %d", Config.StompConfig.Endpoint, string(data), err, i)
			} else {
				log.Printf("unable to send data to %s, error %v, iteration %d", Config.StompConfig.Endpoint, err, i)
			}
			if stompConn != nil {
				stompConn.Disconnect()
			}
			stompConn, err = StompConnection()
		} else {
			if Config.StompConfig.Verbose {
				log.Printf("send data to StompAMQ endpoint %s", Config.StompConfig.Endpoint)
			}
			return
		}
	}
}
