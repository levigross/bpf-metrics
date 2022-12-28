package metrics

import (
	"bytes"
	"context"
	"errors"
	golog "log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/levigross/ebpf-helpers/sys"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const (
	bpfStatsFile = "/proc/sys/kernel/bpf_stats_enabled"
)

var log *zap.Logger

func init() {
	golog.SetOutput(os.Stderr)
	if unix.Getuid() != 0 {
		golog.Fatalln("This program must run as root")
	}
	var err error
	log, err = zap.NewDevelopment()
	if err != nil {
		golog.Fatalf("can't initialize zap logger: %v", err)
	}
	defer log.Sync()
}

type Config struct {
	Port                     uint16
	EnableBPFMetrics         bool
	DisableMetricsOnShutdown bool

	errorChan chan error
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

func (c *Config) collectBPFMetrics(ctx context.Context) {
	bpfProgID := &sys.ProgGetNextIdAttr{Id: 0}
	if err := sys.ProgGetNextId(bpfProgID); err != nil {
		log.Error("Unable to list BPF progs", zap.Error(err))
		c.errorChan <- err
		return
	}
	log.Debug("Found bpf program", zap.Int("prog_id", int(bpfProgID.NextId)))
	for {
		hasMetrics, err := c.hasMetrics(bpfProgID)
		if err != nil {
			c.errorChan <- err
			return
		}
		if !hasMetrics {
			continue
		}

	}

}

func (c *Config) hasMetrics(bpfProg *sys.ProgGetNextIdAttr) (bool, error) {

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
	go c.collectBPFMetrics(ctx)
	select {
	case err := <-c.errorChan:
		return err
	case <-sigInt:
		return nil
	}

	bpfProgID.Id = bpfProgID.NextId // Grab the next ID
	bpfProgID.NextId = 0            // clear the value so it can be populated next program

	for {
		err = sys.ProgGetNextId(bpfProgID)
		if errors.Unwrap(err) == unix.ENOENT {
			break
		}
		if err != nil {
			log.Error("Error getting next BPF program", zap.Error(err))
			return err
		}
		log.Debug("Found bpf program", zap.Int("prog_id", int(bpfProgID.NextId)))
		bpfProgID.Id = bpfProgID.NextId // Grab the next ID
		bpfProgID.NextId = 0
		bpfProgFD := &sys.ProgGetFdByIdAttr{Id: bpfProgID.Id}
		fd, err := sys.ProgGetFdById(bpfProgFD)
		if err != nil {
			log.Error("Unable to get BPF FD", zap.Error(err))
			return err
		}
		var info sys.ProgInfo

		err = sys.ObjInfo(fd, &info)
		if err != nil {
			log.Error("Unable to get object info", zap.Error(err))
			return err
		}
		switch ebpf.ProgramType(info.Type) {
		case ebpf.Kprobe, ebpf.TracePoint, ebpf.PerfEvent:
			log.Info("found probe", zap.String("program name", unix.ByteSliceToString(info.Name[:])))
		}

	}
	return nil

}

// func main() {

// 	bpfProgID := &ProgGetNextIdAttr{Id: 0}
// 	if err := ProgGetNextId(bpfProgID); err != nil {
// 		log.Fatalln("Unable to get next BPF prog", err)
// 	}
// 	for {

// 	}
// }

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
