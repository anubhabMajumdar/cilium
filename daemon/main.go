// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/pkg/hive"
)

func main() {
	// ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	// defer stop()

	_, err := setupOTelSDK(context.Background())
	if err != nil {
		// Fatal error, we cannot continue without OpenTelemetry.
		fmt.Print("failed to set up OpenTelemetry SDK: %w", err)
		os.Exit(1)
	}
	// // Handle shutdown properly so nothing leaks.
	// defer func() {
	// 	err = errors.Join(err, otelShutdown(context.Background()))
	// }()

	hiveFn := func() *hive.Hive {
		return hive.New(cmd.Agent)
	}
	cmd.Execute(cmd.NewAgentCmd(hiveFn))
}
