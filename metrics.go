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

// DataIn represents total data (in bytes) going into APS
var DataIn float64

// DataOut represents total data (in bytes) going out from APS
var DataOut float64

// TotalGetRequests counts total number of GET requests received by the server
var TotalGetRequests uint64

// TotalPostRequests counts total number of POST requests received by the server
var TotalPostRequests uint64

// TotalPutRequests counts total number of PUT requests received by the server
var TotalPutRequests uint64

// TotalDeleteRequests counts total number of DELETE requests received by the server
var TotalDeleteRequests uint64

// TotalHeadRequests counts total number of HEAD requests received by the server
var TotalHeadRequests uint64

// MetricsLastUpdateTime keeps track of last update time of the metrics
var MetricsLastUpdateTime time.Time

// RPS represents requests per second for a given server
var RPS float64

// RPSPhysical represents requests per second for a given server times number of physical CPU cores
var RPSPhysical float64

// RPSLogical represents requests per second for a given server times number of logical CPU cores
var RPSLogical float64

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
	metrics.PutX509Requests = TotalX509PutRequests
	metrics.DeleteX509Requests = TotalX509DeleteRequests
	metrics.HeadX509Requests = TotalX509HeadRequests

	metrics.GetOAuthRequests = TotalOAuthGetRequests
	metrics.PostOAuthRequests = TotalOAuthPostRequests
	metrics.PutOAuthRequests = TotalOAuthPutRequests
	metrics.DeleteOAuthRequests = TotalOAuthDeleteRequests
	metrics.HeadOAuthRequests = TotalOAuthHeadRequests

	metrics.GetRequests = metrics.GetX509Requests + metrics.GetOAuthRequests
	metrics.PostRequests = metrics.PostX509Requests + metrics.PostOAuthRequests
	metrics.PutRequests = metrics.PutX509Requests + metrics.PutOAuthRequests
	metrics.DeleteRequests = metrics.DeleteX509Requests + metrics.DeleteOAuthRequests
	metrics.HeadRequests = metrics.HeadX509Requests + metrics.HeadOAuthRequests

	if (metrics.GetRequests + metrics.PostRequests + metrics.PutRequests + metrics.DeleteRequests + metrics.HeadRequests) > 0 {
		metrics.RPS = RPS / float64(metrics.GetRequests+metrics.PostRequests+metrics.PutRequests+metrics.DeleteRequests+metrics.HeadRequests)
	}
	if (metrics.GetRequests + metrics.PostRequests + metrics.PutRequests + metrics.DeleteRequests + metrics.HeadRequests) > 0 {
		metrics.RPSPhysical = RPSPhysical / float64(metrics.GetRequests+metrics.PostRequests+metrics.PutRequests+metrics.DeleteRequests+metrics.HeadRequests)
	}
	if (metrics.GetRequests + metrics.PostRequests + metrics.PutRequests + metrics.DeleteRequests + metrics.HeadRequests) > 0 {
		metrics.RPSLogical = RPSLogical / float64(metrics.GetRequests+metrics.PostRequests+metrics.PutRequests+metrics.DeleteRequests+metrics.HeadRequests)
	}
	metrics.DataIn = DataIn
	metrics.DataOut = DataOut

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
	out += fmt.Sprintf("# HELP %s_cpu percentage of cpu used per CPU\n", prefix)
	out += fmt.Sprintf("# TYPE %s_cpu gauge\n", prefix)
	for i, v := range data.CPU {
		out += fmt.Sprintf("%s_cpu{core=\"%d\"} %v\n", prefix, i, v)
	}

	// connections
	var totCon, estCon, lisCon uint64
	for _, c := range data.Connections {
		v := c.Status
		switch v {
		case "ESTABLISHED":
			estCon++
		case "LISTEN":
			lisCon++
		}
	}
	totCon = uint64(len(data.Connections))
	out += fmt.Sprintf("# HELP %s_total_connections\n", prefix)
	out += fmt.Sprintf("# TYPE %s_total_connections gauge\n", prefix)
	out += fmt.Sprintf("%s_total_connections %v\n", prefix, totCon)
	out += fmt.Sprintf("# HELP %s_established_connections\n", prefix)
	out += fmt.Sprintf("# TYPE %s_established_connections gauge\n", prefix)
	out += fmt.Sprintf("%s_established_connections %v\n", prefix, estCon)
	out += fmt.Sprintf("# HELP %s_listen_connections\n", prefix)
	out += fmt.Sprintf("# TYPE %s_listen_connections gauge\n", prefix)
	out += fmt.Sprintf("%s_listen_connections %v\n", prefix, lisCon)

	// load
	out += fmt.Sprintf("# HELP %s_load1\n", prefix)
	out += fmt.Sprintf("# TYPE %s_load1 gauge\n", prefix)
	out += fmt.Sprintf("%s_load1 %v\n", prefix, data.Load.Load1)
	out += fmt.Sprintf("# HELP %s_load5\n", prefix)
	out += fmt.Sprintf("# TYPE %s_load5 gauge\n", prefix)
	out += fmt.Sprintf("%s_load5 %v\n", prefix, data.Load.Load5)
	out += fmt.Sprintf("# HELP %s_load15\n", prefix)
	out += fmt.Sprintf("# TYPE %s_load15 gauge\n", prefix)
	out += fmt.Sprintf("%s_load15 %v\n", prefix, data.Load.Load15)

	// memory virtual
	out += fmt.Sprintf("# HELP %s_mem_virt_total reports total virtual memory in bytes\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_virt_total gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_virt_total %v\n", prefix, data.Memory.Virtual.Total)
	out += fmt.Sprintf("# HELP %s_mem_virt_free reports free virtual memory in bytes\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_virt_free gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_virt_free %v\n", prefix, data.Memory.Virtual.Free)
	out += fmt.Sprintf("# HELP %s_mem_virt_used reports used virtual memory in bytes\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_virt_used gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_virt_used %v\n", prefix, data.Memory.Virtual.Used)
	out += fmt.Sprintf("# HELP %s_mem_virt_pct reports percentage of virtual memory\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_virt_pct gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_virt_pct %v\n", prefix, data.Memory.Virtual.UsedPercent)

	// memory swap
	out += fmt.Sprintf("# HELP %s_mem_swap_total reports total swap memory in bytes\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_swap_total gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_swap_total %v\n", prefix, data.Memory.Swap.Total)
	out += fmt.Sprintf("# HELP %s_mem_swap_free reports free swap memory in bytes\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_swap_free gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_swap_free %v\n", prefix, data.Memory.Swap.Free)
	out += fmt.Sprintf("# HELP %s_mem_swap_used reports used swap memory in bytes\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_swap_used gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_swap_used %v\n", prefix, data.Memory.Swap.Used)
	out += fmt.Sprintf("# HELP %s_mem_swap_pct reports percentage swap memory\n", prefix)
	out += fmt.Sprintf("# TYPE %s_mem_swap_pct gauge\n", prefix)
	out += fmt.Sprintf("%s_mem_swap_pct %v\n", prefix, data.Memory.Swap.UsedPercent)

	// open files
	out += fmt.Sprintf("# HELP %s_open_files reports total number of open file descriptors\n", prefix)
	out += fmt.Sprintf("# TYPE %s_open_files gauge\n", prefix)
	out += fmt.Sprintf("%s_open_files %v\n", prefix, len(data.OpenFiles))

	// go routines
	out += fmt.Sprintf("# HELP %s_goroutines reports total number of go routines\n", prefix)
	out += fmt.Sprintf("# TYPE %s_goroutines counter\n", prefix)
	out += fmt.Sprintf("%s_goroutines %v\n", prefix, data.GoRoutines)

	// uptime
	out += fmt.Sprintf("# HELP %s_uptime reports server uptime in seconds\n", prefix)
	out += fmt.Sprintf("# TYPE %s_uptime counter\n", prefix)
	out += fmt.Sprintf("%s_uptime %v\n", prefix, data.Uptime)

	// x509 requests
	out += fmt.Sprintf("# HELP %s_get_x509_requests reports total number of X509 HTTP GET requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_get_x509_requests counter\n", prefix)
	out += fmt.Sprintf("%s_get_x509_requests %v\n", prefix, data.GetX509Requests)

	out += fmt.Sprintf("# HELP %s_post_x509_requests reports total number of X509 HTTP POST requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_post_x509_requests counter\n", prefix)
	out += fmt.Sprintf("%s_post_x509_requests %v\n", prefix, data.PostX509Requests)

	out += fmt.Sprintf("# HELP %s_put_x509_requests reports total number of X509 HTTP PUT requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_put_x509_requests counter\n", prefix)
	out += fmt.Sprintf("%s_put_x509_requests %v\n", prefix, data.PutX509Requests)

	out += fmt.Sprintf("# HELP %s_delete_x509_requests reports total number of X509 HTTP DELETE requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_delete_x509_requests counter\n", prefix)
	out += fmt.Sprintf("%s_delete_x509_requests %v\n", prefix, data.DeleteX509Requests)

	out += fmt.Sprintf("# HELP %s_head_x509_requests reports total number of X509 HTTP HEAD requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_head_x509_requests counter\n", prefix)
	out += fmt.Sprintf("%s_head_x509_requests %v\n", prefix, data.HeadX509Requests)

	// oauth requests
	out += fmt.Sprintf("# HELP %s_get_oauth_requests reports total number of OAuth HTTP GET requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_get_oauth_requests counter\n", prefix)
	out += fmt.Sprintf("%s_get_oauth_requests %v\n", prefix, data.GetOAuthRequests)

	out += fmt.Sprintf("# HELP %s_post_oauth_requests reports total number of OAuth HTTP POST requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_post_oauth_requests counter\n", prefix)
	out += fmt.Sprintf("%s_post_oauth_requests %v\n", prefix, data.PostOAuthRequests)

	out += fmt.Sprintf("# HELP %s_put_oauth_requests reports total number of OAuth HTTP PUT requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_put_oauth_requests counter\n", prefix)
	out += fmt.Sprintf("%s_put_oauth_requests %v\n", prefix, data.PutOAuthRequests)

	out += fmt.Sprintf("# HELP %s_delete_oauth_requests reports total number of OAuth HTTP DELETE requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_delete_oauth_requests counter\n", prefix)
	out += fmt.Sprintf("%s_delete_oauth_requests %v\n", prefix, data.DeleteOAuthRequests)

	out += fmt.Sprintf("# HELP %s_head_oauth_requests reports total number of OAuth HTTP HEAD requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_head_oauth_requests counter\n", prefix)
	out += fmt.Sprintf("%s_head_oauth_requests %v\n", prefix, data.HeadOAuthRequests)

	// total requests
	out += fmt.Sprintf("# HELP %s_get_requests reports total number of HTTP GET requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_get_requests counter\n", prefix)
	out += fmt.Sprintf("%s_get_requests %v\n", prefix, data.GetRequests)

	out += fmt.Sprintf("# HELP %s_post_requests reports total number of HTTP POST requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_post_requests counter\n", prefix)
	out += fmt.Sprintf("%s_post_requests %v\n", prefix, data.PostRequests)

	out += fmt.Sprintf("# HELP %s_put_requests reports total number of HTTP PUT requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_put_requests counter\n", prefix)
	out += fmt.Sprintf("%s_put_requests %v\n", prefix, data.PutRequests)

	out += fmt.Sprintf("# HELP %s_delete_requests reports total number of HTTP DELETE requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_delete_requests counter\n", prefix)
	out += fmt.Sprintf("%s_delete_requests %v\n", prefix, data.DeleteRequests)

	out += fmt.Sprintf("# HELP %s_head_requests reports total number of HTTP HEAD requests\n", prefix)
	out += fmt.Sprintf("# TYPE %s_head_requests counter\n", prefix)
	out += fmt.Sprintf("%s_head_requests %v\n", prefix, data.HeadRequests)

	// data in/data out numbers
	out += fmt.Sprintf("# HELP %s_data_in reports average number of bytes going into HTTP server\n", prefix)
	out += fmt.Sprintf("# TYPE %s_data_in counter\n", prefix)
	out += fmt.Sprintf("%s_data_in %v\n", prefix, data.DataIn)
	out += fmt.Sprintf("# HELP %s_data_out reports average number of bytes going out of HTTP server\n", prefix)
	out += fmt.Sprintf("# TYPE %s_data_out counter\n", prefix)
	out += fmt.Sprintf("%s_data_out %v\n", prefix, data.DataOut)

	// throughput, rps, rps physical cpu, rps logical cpu
	out += fmt.Sprintf("# HELP %s_rps reports request per second average\n", prefix)
	out += fmt.Sprintf("# TYPE %s_rps gauge\n", prefix)
	out += fmt.Sprintf("%s_rps %v\n", prefix, data.RPS)

	out += fmt.Sprintf("# HELP %s_rps_physical_cpu reports request per second average weighted by physical CPU cores\n", prefix)
	out += fmt.Sprintf("# TYPE %s_rps_physical_cpu gauge\n", prefix)
	out += fmt.Sprintf("%s_rps_physical_cpu %v\n", prefix, data.RPSPhysical)

	out += fmt.Sprintf("# HELP %s_rps_logical_cpu reports request per second average weighted by logical CPU cures\n", prefix)
	out += fmt.Sprintf("# TYPE %s_rps_logical_cpu gauge\n", prefix)
	out += fmt.Sprintf("%s_rps_logical_cpu %v\n", prefix, data.RPSLogical)

	return out
}

// helper function that calculates request per second metrics
func getRPS(time0 time.Time) {
	RPS += 1. / time.Since(time0).Seconds()
	RPSLogical += float64(NumLogicalCores) / time.Since(time0).Seconds()
	RPSPhysical += float64(NumPhysicalCores) / time.Since(time0).Seconds()
}
