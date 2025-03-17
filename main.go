package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"subs-check-custom/types"
)

type crlfWriter struct {
	Writer io.Writer
}

func (w *crlfWriter) Write(p []byte) (n int, err error) {
	p = []byte(strings.ReplaceAll(string(p), "\n", "\r\n"))
	return w.Writer.Write(p)
}

func main() {
	logFile, err := os.Create("runlog.txt")
	if err != nil {
		fmt.Printf("Failed to create runlog.txt: %v\n", err)
		return
	}
	defer logFile.Close()
	log.SetOutput(&crlfWriter{Writer: logFile})

	simpleLogFile, err := os.Create("parsingLog.txt")
	if err != nil {
		log.Printf("Failed to create parsingLog.txt: %v", err)
		return
	}
	defer simpleLogFile.Close()
	simpleLogger := log.New(&crlfWriter{Writer: simpleLogFile}, "", 0)

	configFile := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	var config types.Config
	if _, err := os.Stat(*configFile); err == nil {
		configData, err := os.ReadFile(*configFile)
		if err != nil {
			log.Fatalf("Failed to read config file %s: %v", *configFile, err)
		}
		if err := yaml.Unmarshal(configData, &config); err != nil {
			log.Fatalf("Config parse failed: %v", err)
		}
	} else {
		log.Printf("Config file %s not found, using default config", *configFile)
		config = types.Config{
			SpeedTestURL:    "https://speed.cloudflare.com/__down?bytes=10485760",
			Concurrent:      5,
			Timeout:         15000,
			MinSpeed:        256,
			SaveMethod:      "local",
			GistToken:       os.Getenv("GIST_TOKEN"),
			GistID:          os.Getenv("GIST_ID"),
			SubURLs:         []string{},
			ProxyAddr:       "127.0.0.1:10808",
			ApiAddr:         "127.0.0.1:10085", // Default API address for Xray
			AllOutputFile:   "all.yaml",
			UniqueNodesFile: "uniqueNodes.txt",
			TCPTestURL:      "https://www.apple.com/library/test/success.html",
			TCPTestMaxSpeed: 3000,
		}
	}

	if token := os.Getenv("GIST_TOKEN"); token != "" {
		config.GistToken = token
	}
	if gistID := os.Getenv("GIST_ID"); gistID != "" {
		config.GistID = gistID
	}

	updateProgress := func(stageName string) {
		fmt.Printf("\033[2K\rStage: %s\n", stageName)
	}

	fmt.Println("There are 4 stages: Fetching, Parsing, Testing (optional), Saving")

	// Prompt user for test selection with 5-second timeout
	fmt.Print("Select test: (0) No test, (1) TCP test, (2) Download speed test, (3) Both [default 0 in 5s]: ")
	choiceChan := make(chan string, 1)
	go func() {
		var choice string
		_, err := fmt.Scanln(&choice)
		if err != nil {
			choice = "0" // Default to 0 on error (e.g., no input)
		}
		choiceChan <- choice
	}()

	var testChoice string
	select {
	case choice := <-choiceChan:
		testChoice = choice
	case <-time.After(5 * time.Second):
		testChoice = "0"
		fmt.Println("\nDefaulting to (0) No test")
	}

	// Fetch content
	content, err := fetchContent(config, updateProgress)
	if err != nil {
		return // Error already logged in fetchContent
	}

	updateProgress("Parsing")
	stats := types.ProxyStats{}
	nodes := fetchNodes(content, simpleLogger, &stats)

	simpleLogger.Printf("Total Success: %d", stats.TotalSuccess)
	simpleLogger.Printf("Total Fail: %d", stats.TotalFail)
	simpleLogger.Printf("SS Success: %d, SS Fail: %d", stats.SSSuccess, stats.SSFail)
	simpleLogger.Printf("VMess Success: %d, VMess Fail: %d", stats.VMessSuccess, stats.VMessFail)
	simpleLogger.Printf("Trojan Success: %d, Trojan Fail: %d", stats.TrojanSuccess, stats.TrojanFail)
	simpleLogger.Printf("Hysteria2 Success: %d, Hysteria2 Fail: %d", stats.Hysteria2Success, stats.Hysteria2Fail)
	simpleLogger.Printf("VLess Success: %d, VLess Fail: %d", stats.VLessSuccess, stats.VLessFail)
	simpleLogger.Println("--- Parsing Results ---")

	var tested []types.Proxy
	updateProgress("Testing")
	tested = testNodes(config, nodes, testChoice)

	updateProgress("Saving")
	saveResults(config, tested)

	updateProgress("Completed")
	fmt.Println()
	fmt.Println("Build and run completed!")
}
