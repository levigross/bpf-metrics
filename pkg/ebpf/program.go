package ebpf

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/levigross/ebpf-helpers/sys"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

type Program struct {
	Name string
	Id   string

	ebpfProgramFD *sys.FD

	runCount, runTimeNs uint64
}

const (
	system = "ebpf_metrics"
)

var (
	durationNS = prometheus.NewDesc(
		prometheus.BuildFQName(system, "", "run_time"),
		"Number of times the BPF program ran (in nanoseconds)", []string{"name", "id"}, nil)
	runCount = prometheus.NewDesc(
		prometheus.BuildFQName(system, "", "run_count"),
		"Number of times the BPF program ran", []string{"name", "id"}, nil)

	programCollection      []*Program
	programCollectionMutex sync.RWMutex
)

func NewProgram(name string, id uint32, fd *sys.FD) *Program {
	return &Program{
		Name:          name,
		Id:            fmt.Sprint(id),
		ebpfProgramFD: fd,
	}
}

func (p *Program) Update() error {
	var info sys.ProgInfo
	if err := sys.ObjInfo(p.ebpfProgramFD, &info); err != nil {
		return err
	}
	p.runCount = info.RunCnt
	p.runTimeNs = info.RunTimeNs
	return nil
}

func (p *Program) getDurationNS() float64 {
	return float64(p.runTimeNs)
}

func (p *Program) getRunCount() float64 {
	return float64(p.runCount)
}

func CollectProgramMetrics(p *Program) {
	programCollectionMutex.Lock()
	defer programCollectionMutex.Unlock()
	programCollection = append(programCollection, p)
}

func NewMetricsCollector(reg prometheus.Registerer) *MetricsCollector {
	mc := &MetricsCollector{}
	reg.MustRegister(mc)
	return mc
}

type MetricsCollector struct{}

func (m *MetricsCollector) Describe(pd chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(m, pd)
}

func (m *MetricsCollector) Collect(metricChan chan<- prometheus.Metric) {
	programCollectionMutex.RLock()
	defer programCollectionMutex.RUnlock()
	for _, p := range programCollection {
		if err := p.Update(); err != nil { // TODO remove the ones that error out (they may not exist)
			continue
		}
		metricChan <- prometheus.MustNewConstMetric(durationNS, prometheus.CounterValue, p.getDurationNS(), p.Name, p.Id)
		metricChan <- prometheus.MustNewConstMetric(runCount, prometheus.CounterValue, p.getRunCount(), p.Name, p.Id)
	}
}

var _ prometheus.Collector = &MetricsCollector{}

// TODO move to metrics package
func RunMetricsListener(ctx context.Context, portNumber uint16) error {
	reg := prometheus.NewPedanticRegistry()
	NewMetricsCollector(reg)
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector())
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	return http.ListenAndServe(fmt.Sprintf(":%d", portNumber), nil) // TODO add the context
}

func CollectMetrics(ctx context.Context) error {
	timer := time.NewTimer(time.Second * 10)
	defer timer.Stop()
	for range timer.C {
		bpfProgID := &sys.ProgGetNextIdAttr{Id: 0}
		err := sys.ProgGetNextId(bpfProgID)
		if errors.Unwrap(err) == unix.ENONET {
			continue
		}

		if err != nil {
			return err
		}

		bpfProgID.Id = bpfProgID.NextId // set our ID to the program found
		bpfProgID.NextId = 0            // Clear the next ID so we can enumerate all of the BPF programs
		for {
			err = sys.ProgGetNextId(bpfProgID)
			if errors.Unwrap(err) == unix.ENOENT {
				break
			}
			bpfProgFD := &sys.ProgGetFdByIdAttr{Id: bpfProgID.Id}
			fd, err := sys.ProgGetFdById(bpfProgFD)
			if err != nil {
				return err
			}
			var info sys.ProgInfo
			err = sys.ObjInfo(fd, &info)
			if err != nil {
				return err
			}
			switch ebpf.ProgramType(info.Type) {
			case ebpf.Kprobe, ebpf.TracePoint, ebpf.PerfEvent:
				p := NewProgram(unix.ByteSliceToString(info.Name[:]), info.Id, fd)
				CollectProgramMetrics(p)
			}
			bpfProgID.Id = bpfProgID.NextId // set our ID to the program found
			bpfProgID.NextId = 0            // Clear the next ID so we can enumerate all of the BPF programs
		}
	}
	return nil
}
