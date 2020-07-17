// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package network

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

var h harness.Harness

func BenchmarkIperf(b *testing.B) {
	time := 10 // time in seconds to run the client.

	clientMachine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer clientMachine.CleanUp()

	serverMachine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer serverMachine.CleanUp()
	ctx := context.Background()
	for _, bm := range []struct {
		name       string
		clientFunc func(context.Context, testutil.Logger) *dockerutil.Container
		serverFunc func(context.Context, testutil.Logger) *dockerutil.Container
	}{
		// We are either measuring the server or the client. The other should be
		// runc. e.g. Upload sees how fast the runtime under test uploads to a native
		// server.
		{
			name:       "Upload",
			clientFunc: clientMachine.GetContainer,
			serverFunc: serverMachine.GetNativeContainer,
		},
		{
			name:       "Download",
			clientFunc: clientMachine.GetNativeContainer,
			serverFunc: serverMachine.GetContainer,
		},
	} {
		b.Run(bm.name, func(b *testing.B) {
			// Set up the conatiners.
			server := bm.serverFunc(ctx, b)
			defer server.CleanUp(ctx)
			client := bm.clientFunc(ctx, b)
			defer client.CleanUp(ctx)

			// iperf serves on port 5001 by default.
			port := 5001

			// Start the server.
			if err := server.Spawn(ctx, dockerutil.RunOpts{
				Image: "benchmarks/iperf",
				Ports: []int{port},
			}, "iperf", "-s"); err != nil {
				b.Fatalf("failed to start server with: %v", err)
			}

			ip, err := serverMachine.IPAddress()
			if err != nil {
				b.Fatalf("failed to find server ip: %v", err)
			}

			servingPort, err := server.FindPort(ctx, port)
			if err != nil {
				b.Fatalf("failed to find port %d: %v", port, err)
			}

			// Make sure the server is up and serving before we run.
			if err := harness.WaitUntilServing(ctx, clientMachine, ip, servingPort); err != nil {
				b.Fatalf("failed to wait for server: %v", err)
			}

			// iperf report in Kb realtime
			cmd := fmt.Sprintf("iperf -f K --realtime --time %d -c %s -p %d", time, ip.String(), servingPort)

			// Run the client.
			b.ResetTimer()

			// Restart the server profiles. If the server isn't being profiled
			// this does nothing.
			server.RestartProfiles()
			for i := 0; i < b.N; i++ {
				out, err := client.Run(ctx, dockerutil.RunOpts{
					Image: "benchmarks/iperf",
				}, strings.Split(cmd, " ")...)
				if err != nil {
					b.Fatalf("failed to run client: %v", err)
				}
				b.StopTimer()

				// Parse bandwidth and report it.
				bW, err := bandwidth(out)
				if err != nil {
					b.Fatalf("failed to parse bandwitdth from %s: %v", out, err)
				}
				b.ReportMetric(bW*1024, "bandwidth") // Convert from Kb/s to b/s.
				b.StartTimer()
			}
		})
	}
}

// bandwidth parses the Bandwidth number from an iperf report. A sample is below.
func bandwidth(data string) (float64, error) {
	re := regexp.MustCompile(`\[\s*\d+\][^\n]+\s+(\d+\.?\d*)\s+KBytes/sec`)
	match := re.FindStringSubmatch(data)
	if len(match) < 1 {
		return 0, fmt.Errorf("failed get bandwidth: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}

func TestParser(t *testing.T) {
	sampleData := `
------------------------------------------------------------
Client connecting to 10.138.15.215, TCP port 32779
TCP window size: 45.0 KByte (default)
------------------------------------------------------------
[  3] local 10.138.15.216 port 32866 connected with 10.138.15.215 port 32779
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0-10.0 sec  459520 KBytes  45900 KBytes/sec
`
	bandwidth, err := bandwidth(sampleData)
	if err != nil || bandwidth != 45900 {
		t.Fatalf("failed with: %v and %f", err, bandwidth)
	}

}

func TestMain(m *testing.M) {
	h.Init()
	os.Exit(m.Run())
}
