package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"subs-check-custom/types"

	// Xray-core imports
    xnet "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/app/dispatcher"
    "github.com/xtls/xray-core/app/proxyman"
    "github.com/xtls/xray-core/app/proxyman/command"
    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/common/serial"
    "github.com/xtls/xray-core/core"
    "github.com/xtls/xray-core/proxy/vless"
    "github.com/xtls/xray-core/proxy/vless/outbound"
    "github.com/xtls/xray-core/transport/internet"
)

// dialContextAdapter adapts a proxy.Dialer to a DialContext function
type dialContextAdapter struct {
	dialer proxy.Dialer
}

func (d *dialContextAdapter) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	connChan := make(chan net.Conn, 1)
	errChan := make(chan error, 1)

	go func() {
		conn, err := d.dialer.Dial(network, addr)
		if err != nil {
			errChan <- err
			return
		}
		connChan <- conn
	}()

	select {
	case conn := <-connChan:
		return conn, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// tcpTest tests HTTP connectivity to cfg.TCPTestURL through Xray's SOCKS5 proxy
func tcpTest(cfg types.Config, nodes []types.Proxy, testLogger *log.Logger) []types.Proxy {
	var wg sync.WaitGroup
	testedNodes := make([]types.Proxy, 0, len(nodes)) // Only successful nodes
	mutex := &sync.Mutex{}
	successCount := 0
	failedCount := 0
	const maxRetries = 2 // Number of retries for each node

	// Connect to Xray's API using the configured address
	conn, err := grpc.Dial(cfg.ApiAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		testLogger.Printf("Failed to connect to Xray API at %s: %v", cfg.ApiAddr, err)
		return nodes
	}
	defer conn.Close()

	client := command.NewHandlerServiceClient(conn)

	for i, node := range nodes {
		wg.Add(1)
		testLogger.Printf("Node %d: Switching to %s:%d (%s)", i, node.Server, node.Port, node.Name)

		// Switch to the current node using the API
		err := switchNode(client, node, i)
		if err != nil {
			testLogger.Printf("Node %d: Failed to switch to %s:%d (%s): %v", i, node.Server, node.Port, node.Name, err)
			failedCount++
			wg.Done()
			continue
		}

		testLogger.Printf("Node %d: Running TCP test to %s (Name: %s)", i, cfg.TCPTestURL, node.Name)
		go func(n types.Proxy, nodeIndex int) {
			defer wg.Done()

			var lastErr error
			for attempt := 0; attempt <= maxRetries; attempt++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout*2)*time.Millisecond) // Double the timeout
				defer cancel()

				// Use Xray's SOCKS5 proxy
				dialer, err := proxy.SOCKS5("tcp", cfg.ProxyAddr, nil, proxy.Direct)
				if err != nil {
					testLogger.Printf("Node %d: Fail - Failed to create SOCKS5 dialer for %s (%v)", nodeIndex, cfg.ProxyAddr, err)
					failedCount++
					return
				}
				adapter := &dialContextAdapter{dialer: dialer}
				transport := &http.Transport{
					DialContext: adapter.DialContext,
				}
				client := &http.Client{
					Transport: transport,
					Timeout:   time.Duration(cfg.Timeout*2) * time.Millisecond, // Double the timeout
				}

				req, err := http.NewRequestWithContext(ctx, "GET", cfg.TCPTestURL, nil)
				if err != nil {
					testLogger.Printf("Node %d: Fail - Failed to create request (%v)", nodeIndex, err)
					failedCount++
					return
				}

				start := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					lastErr = err
					testLogger.Printf("Node %d: Attempt %d failed - TCP test failed for %s (%v)", nodeIndex, attempt+1, n.Name, err)
					if attempt < maxRetries {
						time.Sleep(time.Second) // Wait 1 second before retrying
						continue
					}
					testLogger.Printf("Node %d: Fail - TCP test failed for %s after %d attempts (%v)", nodeIndex, n.Name, maxRetries+1, lastErr)
					failedCount++
					return
				}
				defer resp.Body.Close()

				// Check if response is successful (status 200)
				if resp.StatusCode != http.StatusOK {
					lastErr = fmt.Errorf("non-200 status: %d", resp.StatusCode)
					testLogger.Printf("Node %d: Attempt %d failed - TCP test received non-200 status (%d) for %s", nodeIndex, attempt+1, resp.StatusCode, n.Name)
					if attempt < maxRetries {
						time.Sleep(time.Second)
						continue
					}
					testLogger.Printf("Node %d: Fail - TCP test failed for %s after %d attempts (non-200 status: %d)", nodeIndex, n.Name, maxRetries+1, resp.StatusCode)
					failedCount++
					return
				}

				duration := time.Since(start).Milliseconds()
				if duration > int64(cfg.TCPTestMaxSpeed) {
					testLogger.Printf("Node %d: Fail - TCP test exceeded max speed (%d ms > %d ms) for %s", nodeIndex, duration, cfg.TCPTestMaxSpeed, n.Name)
					failedCount++
					return
				}

				testLogger.Printf("Node %d: Success - TCP test passed (%d ms) for %s", nodeIndex, duration, n.Name)
				mutex.Lock()
				n.Latency = duration // Store latency in the node struct
				testedNodes = append(testedNodes, n)
				successCount++
				mutex.Unlock()
				return // Success, no need to retry
			}
		}(node, i)
	}
	wg.Wait()

	testLogger.Printf("TCP Test - Total nodes: %d, Successful: %d, Failed: %d", len(nodes), successCount, failedCount)
	return testedNodes
}

func switchNode(client command.HandlerServiceClient, node types.Proxy, nodeIndex int) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // Create a VLESS outbound configuration for the node
    user := &protocol.User{
        Account: serial.ToTypedMessage(&vless.Account{
            Id: node.UUID,
        }),
    }

    // Construct the VLESS outbound configuration
    streamSetting := &proxyman.StreamConfig{
        Protocol: "http", // Use "http" as a proxy for WebSocket
        Settings: serial.ToTypedMessage(&internet.WebSocketConfig{
            Path: node.Path,
        }),
        Security: "tls",
        TlsSettings: serial.ToTypedMessage(&internet.TLSConfig{
            ServerName: node.SNI,
        }),
    }

    outboundConfig := &core.Config{
        Outbound: []*core.OutboundHandlerConfig{
            {
                Tag:           fmt.Sprintf("proxy_%d", nodeIndex),
                ProxySettings: serial.ToTypedMessage(&outbound.Config{
                    Vnext: []*protocol.ServerEndpoint{
                        {
                            Address: xnet.ParseAddress(node.Server),
                            Port:    uint32(node.Port),
                            User:    user,
                        },
                    },
                }),
                SenderSettings: serial.ToTypedMessage(&dispatcher.Config{}),
                StreamSetting:  serial.ToTypedMessage(streamSetting),
            },
        },
    }

    // Remove existing outbound if it exists
    _, err := client.RemoveOutbound(ctx, &command.RemoveOutboundRequest{
        Tag: fmt.Sprintf("proxy_%d", nodeIndex),
    })
    // Ignore error if outbound doesn't exist

    // Add the new outbound
    _, err = client.AddOutbound(ctx, &command.AddOutboundRequest{Outbound: outboundConfig})
    if err != nil {
        return fmt.Errorf("failed to add outbound: %v", err)
    }

    return nil
}

// speedTest performs the download speed test on nodes
func speedTest(cfg types.Config, nodes []types.Proxy, testLogger *log.Logger) []types.Proxy {
	totalNodes := len(nodes)
	fmt.Printf("Total nodes to speed test: %d\n", totalNodes)

	var wg sync.WaitGroup
	testedNodes := make([]types.Proxy, len(nodes))
	copy(testedNodes, nodes)

	mutex := &sync.Mutex{}
	successCount := 0
	failedCount := 0
	completedCount := 0
	var countMutex sync.Mutex

	for i := 0; i < len(nodes); i += cfg.Concurrent {
		end := i + cfg.Concurrent
		if end > len(nodes) {
			end = len(nodes)
		}
		batch := nodes[i:end]
		wg.Add(len(batch))
		for idx, node := range batch {
			nodeIndex := i + idx
			testLogger.Printf("Node %d: Running speed test", nodeIndex)
			go func(n types.Proxy, nodeIndex int) {
				defer wg.Done()

				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Millisecond)
				defer cancel()

				dialer, err := proxy.SOCKS5("tcp", cfg.ProxyAddr, nil, proxy.Direct)
				if err != nil {
					countMutex.Lock()
					failedCount++
					completedCount++
					testLogger.Printf("Node %d: Fail - Failed to create SOCKS5 dialer (%v)", nodeIndex, err)
					fmt.Printf("\rNodes speed tested: %d/%d", completedCount, totalNodes)
					countMutex.Unlock()
					return
				}
				adapter := &dialContextAdapter{dialer: dialer}
				transport := &http.Transport{
					DialContext: adapter.DialContext,
				}
				client := &http.Client{
					Transport: transport,
					Timeout:   time.Duration(cfg.Timeout) * time.Millisecond,
				}

				req, err := http.NewRequestWithContext(ctx, "GET", cfg.SpeedTestURL, nil)
				if err != nil {
					countMutex.Lock()
					failedCount++
					completedCount++
					testLogger.Printf("Node %d: Fail - Failed to create request (%v)", nodeIndex, err)
					fmt.Printf("\rNodes speed tested: %d/%d", completedCount, totalNodes)
					countMutex.Unlock()
					return
				}
				start := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					countMutex.Lock()
					failedCount++
					completedCount++
					testLogger.Printf("Node %d: Fail - Speed test failed (%v)", nodeIndex, err)
					fmt.Printf("\rNodes speed tested: %d/%d", completedCount, totalNodes)
					countMutex.Unlock()
					return
				}
				defer resp.Body.Close()

				var totalBytes int64
				buf := make([]byte, 1024)
				for {
					select {
					case <-ctx.Done():
						countMutex.Lock()
						failedCount++
						completedCount++
						testLogger.Printf("Node %d: Fail - Speed test timeout", nodeIndex)
						fmt.Printf("\rNodes speed tested: %d/%d", completedCount, totalNodes)
						countMutex.Unlock()
						return
					default:
						bytesRead, err := resp.Body.Read(buf)
						totalBytes += int64(bytesRead)
						if err != nil {
							countMutex.Lock()
							completedCount++
							if err == io.EOF {
								duration := time.Since(start).Seconds()
								if duration == 0 {
									failedCount++
									testLogger.Printf("Node %d: Fail - Speed test duration zero", nodeIndex)
								} else {
									speed := float64(totalBytes) / duration / 1024 // KB/s
									mutex.Lock()
									testedNodes[nodeIndex].Speed = speed
									mutex.Unlock()
									if speed >= float64(cfg.MinSpeed) {
										successCount++
										testLogger.Printf("Node %d: Success - Speed test passed (%.1f KB/s)", nodeIndex, speed)
									} else {
										failedCount++
										testLogger.Printf("Node %d: Fail - Speed below minimum (%.1f KB/s)", nodeIndex, speed)
									}
								}
							} else {
								failedCount++
								testLogger.Printf("Node %d: Fail - Speed test read error (%v)", nodeIndex, err)
							}
							fmt.Printf("\rNodes speed tested: %d/%d", completedCount, totalNodes)
							countMutex.Unlock()
							return
						}
					}
				}
			}(node, nodeIndex)
		}
		wg.Wait()
	}

	fmt.Printf("\nSpeed test completed: %d/%d nodes tested\n", completedCount, totalNodes)
	testLogger.Printf("Speed Test - Total nodes: %d, Successful: %d, Failed: %d", totalNodes, successCount, failedCount)
	return testedNodes
}

func testNodes(cfg types.Config, nodes []types.Proxy, testChoice string) []types.Proxy {
	testLogFile, err := os.OpenFile("testNodeLog.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Failed to create testNodeLog.txt: %v", err)
		return nodes
	}
	defer testLogFile.Close()
	testLogger := log.New(testLogFile, "", 0)

	switch testChoice {
	case "0":
		testLogger.Println("No tests selected, returning all nodes")
		return nodes
	case "1":
		testLogger.Println("Running TCP test only")
		return tcpTest(cfg, nodes, testLogger)
	case "2":
		testLogger.Println("Running Download speed test only")
		return speedTest(cfg, nodes, testLogger)
	case "3":
		testLogger.Println("Running both TCP and Download speed tests")
		tcpPassed := tcpTest(cfg, nodes, testLogger)
		return speedTest(cfg, tcpPassed, testLogger)
	default:
		testLogger.Printf("Invalid choice '%s', defaulting to no test", testChoice)
		return nodes
	}
}
