package metrics

import (
	"bytes"
	"context"
	"os"
	"os/signal"

	"github.com/levigross/bpf-metrics/pkg/ebpf"
	"go.uber.org/zap"
)

const (
	bpfStatsFile = "/proc/sys/kernel/bpf_stats_enabled"
)

var log *zap.Logger = zap.NewExample()

type Config struct {
	Port                     uint16
	EnableBPFMetrics         bool
	DisableMetricsOnShutdown bool
	errorChan                chan error
}

func (c *Config) enableBPFMetrics() error {
	status, err := os.ReadFile(bpfStatsFile)
	if err != nil {
		log.Error("Unable to read ebpf stats file", zap.Error(err))
		return err
	}
	if bytes.Equal(status, []byte("1")) {
		return nil
	}
	if err := enableBPFStats(); err != nil {
		log.Error("Unable to write to ebpf stats file", zap.Error(err))
		return err
	}
	return nil
}

func (c *Config) Run() error {

	c.errorChan = make(chan error, 1)
	sigInt := make(chan os.Signal, 1)
	signal.Notify(sigInt, os.Interrupt)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if c.EnableBPFMetrics {
		c.enableBPFMetrics()
	}
	if c.DisableMetricsOnShutdown {
		defer disableBPFMetrics()
	}

	go func() {
		c.errorChan <- ebpf.CollectMetrics(ctx)
	}()

	go func() {
		c.errorChan <- ebpf.RunMetricsListener(ctx, c.Port)
	}()

	select {
	case err := <-c.errorChan:
		return err
	case <-sigInt:
		return nil
	}
}

func enableBPFStats() error {
	err := os.WriteFile(bpfStatsFile, []byte("1"), 0o666)
	if err != nil {
		log.Error("Unable to enable BPF stats", zap.Error(err))
	}
	return err
}

func disableBPFMetrics() {
	err := os.WriteFile(bpfStatsFile, []byte("0"), 0o666)
	if err != nil {
		log.Error("Unable to disable BPF stats", zap.Error(err))
	}
}
