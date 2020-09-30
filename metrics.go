package main

// metrics module provides various metrics about our server
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet AT gmail dot com>

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/process"
)

// TotalGetRequests counts total number of GET requests received by the server
var TotalGetRequests uint64

// TotalPostRequests counts total number of POST requests received by the server
var TotalPostRequests uint64

// MetricsLastUpdateTime
var MetricsLastUpdateTime time.Time

// RPS represents requests per second for a given server
var RPS float64

func metrics() Metrics {

	// get cpu and mem profiles
	m, _ := mem.VirtualMemory()
	s, _ := mem.SwapMemory()
	l, _ := load.Avg()
	c, _ := cpu.Percent(time.Millisecond, true)
	process, perr := process.NewProcess(int32(os.Getpid()))

	// get unfinished queries
	metrics := Metrics{}
	metrics.GoRoutines = uint64(runtime.NumGoroutine())
	virt := Memory{Total: m.Total, Free: m.Free, Used: m.Used, UsedPercent: m.UsedPercent}
	swap := Memory{Total: s.Total, Free: s.Free, Used: s.Used, UsedPercent: s.UsedPercent}
	metrics.Memory = Mem{Virtual: virt, Swap: swap}
	metrics.Load = *l
	metrics.CPU = c
	if perr == nil { // if we got process info
		conn, err := process.Connections()
		if err == nil {
			metrics.Connections = conn
		}
		openFiles, err := process.OpenFiles()
		if err == nil {
			metrics.OpenFiles = openFiles
		}
	}
	metrics.Uptime = time.Since(StartTime).Seconds()
	metrics.GetX509Requests = TotalX509GetRequests
	metrics.PostX509Requests = TotalX509PostRequests
	metrics.GetOAuthRequests = TotalOAuthGetRequests
	metrics.PostOAuthRequests = TotalOAuthPostRequests
	metrics.GetRequests = metrics.GetX509Requests + metrics.GetOAuthRequests
	metrics.PostRequests = metrics.PostX509Requests + metrics.PostOAuthRequests
	metrics.RequestsPerSecond = RPS

	// update time stamp
	MetricsLastUpdateTime = time.Now()

	return metrics
}

// helper function to generate metrics in prometheus format
func promMetrics() string {
	var out string
	data := metrics()
	prefix := "proxy_server"

	// cpu info
	out += fmt.Sprintf("# HELP %s_cpu\n", prefix)
	out += fmt.Sprintf("# TYPE %s_cpu gauge\n", prefix)
	for i, v := range data.CPU {
		out += fmt.Sprintf("%s_cpu{core=%d} %v\n", prefix, i, v)
	}

	// connections
	var totCon, estCon, lisCon uint64
	for _, c := range data.Connections {
		v := c.Status
		switch v {
		case "ESTABLISHED":
			estCon += 1
		case "LISTEN":
			lisCon += 1
		}
	}
	totCon = uint64(len(data.Connections))
	out += fmt.Sprintf("# HELP %s_total_connections\n", prefix)
	out += fmt.Sprintf("# TYPE %s_total_connections gauge\n", prefix)
	out += fmt.Sprintf("%s_total_connections gauge %v\n", prefix, totCon)
	out += fmt.Sprintf("# HELP %s_established_connections\n", prefix)
	out += fmt.Sprintf("# TYPE %s_established_connections gauge\n", prefix)
	out += fmt.Sprintf("%s_established_connections gauge %v\n", prefix, estCon)
	out += fmt.Sprintf("# HELP %s_listen_connections\n", prefix)
	out += fmt.Sprintf("# TYPE %s_listen_connections gauge\n", prefix)
	out += fmt.Sprintf("%s_listen_connections gauge %v\n", prefix, lisCon)

	// load
	out += fmt.Sprintf("# HELP %s_load1\n", prefix)
	out += fmt.Sprintf("# TYPE %s_load1 gauge\n", prefix)
	out += fmt.Sprintf("%s_load1 gauge %v\n", prefix, data.Load.Load1)
	out += fmt.Sprintf("# HELP %s_load5\n", prefix)
	out += fmt.Sprintf("# TYPE %s_load5 gauge\n", prefix)
	out += fmt.Sprintf("%s_load5 gauge %v\n", prefix, data.Load.Load5)
	out += fmt.Sprintf("# HELP %s_load15\n", prefix)
	out += fmt.Sprintf("# TYPE %s_load15 gauge\n", prefix)
	out += fmt.Sprintf("%s_load15 gauge %v\n", prefix, data.Load.Load15)

	// memory virtual
	out += fmt.Sprintf("# HELP %s_mem_virt_total\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_virt_total gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_virt_total %v\n", prefix, data.Memory.Virtual.Total)
	out += fmt.Sprintf("# HELP %s_mem_virt_free\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_virt_free gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_virt_free %v\n", prefix, data.Memory.Virtual.Free)
	out += fmt.Sprintf("# HELP %s_mem_virt_used\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_virt_used gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_virt_used %v\n", prefix, data.Memory.Virtual.Used)
	out += fmt.Sprintf("# HELP %s_mem_virt_pct\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_virt_pct gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_virt_pct %v\n", prefix, data.Memory.Virtual.UsedPercent)

	// memory swap
	out += fmt.Sprintf("# HELP %s_mem_swap_total\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_swap_total gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_swap_total %v\n", prefix, data.Memory.Swap.Total)
	out += fmt.Sprintf("# HELP %s_mem_swap_free\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_swap_free gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_swap_free %v\n", prefix, data.Memory.Swap.Free)
	out += fmt.Sprintf("# HELP %s_mem_swap_used\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_swap_used gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_swap_used %v\n", prefix, data.Memory.Swap.Used)
	out += fmt.Sprintf("# HELP %s_mem_swap_pct\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_swap_pct gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_swap_pct %v\n", prefix, data.Memory.Swap.UsedPercent)

	// open files
	out += fmt.Sprintf("# HELP %s_open_files\n", prefix)
	out += fmt.Sprintf("# TYPE %s_open_files gauge\n", prefix)
	out += fmt.Sprintf("%s_open_files %v\n", prefix, len(data.OpenFiles))

	// go routines
	out += fmt.Sprintf("# HELP %s_goroutines\n", prefix)
	out += fmt.Sprintf("# TYPE %s_goroutines counter\n", prefix)
	out += fmt.Sprintf("%s_goroutines %v\n", prefix, data.GoRoutines)

	// uptime
	out += fmt.Sprintf("# HELP %s_uptime\n", prefix)
	out += fmt.Sprintf("# TYPE %s_uptime counter\n", prefix)
	out += fmt.Sprintf("%s_uptime %v\n", prefix, data.Uptime)

	// x509 requests
	out += fmt.Sprintf("# HELP %s_get_x509_requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_get_x509_requests counter\n", prefix)
	out += fmt.Sprintf("%s_get_x509_requests %v\n", prefix, data.GetX509Requests)
	out += fmt.Sprintf("# HELP %s_post_x509_requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_post_x509_requests counter\n", prefix)
	out += fmt.Sprintf("%s_post_x509_requests %v\n", prefix, data.PostX509Requests)
	// oauth requests
	out += fmt.Sprintf("# HELP %s_get_oauth_requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_get_oauth_requests counter\n", prefix)
	out += fmt.Sprintf("%s_get_oauth_requests %v\n", prefix, data.GetOAuthRequests)
	out += fmt.Sprintf("# HELP %s_post_oauth_requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_post_oauth_requests counter\n", prefix)
	out += fmt.Sprintf("%s_post_oauth_requests %v\n", prefix, data.PostOAuthRequests)

	// total requests
	out += fmt.Sprintf("# HELP %s_get_requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_get_requests counter\n", prefix)
	out += fmt.Sprintf("%s_get_requests %v\n", prefix, data.GetRequests)
	out += fmt.Sprintf("# HELP %s_post_requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_post_requests counter\n", prefix)
	out += fmt.Sprintf("%s_post_requests %v\n", prefix, data.PostRequests)

	// throughput
	out += fmt.Sprintf("# HELP %s_request_per_second\n", prefix)
	out += fmt.Sprintf("# TYPE %s_request_per_second counter\n", prefix)
	out += fmt.Sprintf("%s_request_per_second %v\n", prefix, data.RequestsPerSecond)

	return out
}

// rps returns request per second
func getRPS(time0 time.Time, totalRequests uint64) {
	// RPS = Num. cores * (1 /Task time)
	// here we set average RPS across all received requests
	RPS = float64(NumCores) / time.Since(time0).Seconds() / float64(totalRequests)
}
