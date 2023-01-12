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
	"github.com/levigross/logger/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
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

	programCollection      = map[string]*Program{}
	programCollectionMutex sync.Mutex

	log = logger.WithName("ebpf")
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
		log.Error("Unable to obtain object info", zap.Any("bpfProgram", p), zap.Error(err))
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
	if _, ok := programCollection[p.Name+p.Id]; ok {
		return
	}
	log.Info("Adding ebpf program for metrics collection", zap.Any("bpfProgram", p))
	programCollection[p.Name+p.Id] = p // Todo make this cleaner
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
	programCollectionMutex.Lock()
	defer programCollectionMutex.Unlock()
	for _, p := range programCollection {
		if err := p.Update(); err != nil {
			log.Info("Removing program with error", zap.Any("program", p))
			delete(programCollection, p.Name+p.Id)
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
	timer := time.NewTicker(time.Second * 10)
	defer timer.Stop()
	for range timer.C {
		log.Debug("Fetching ebpf metrics")
		bpfProgID := &sys.ProgGetNextIdAttr{Id: 0}
		err := sys.ProgGetNextId(bpfProgID)

		if err != nil && errors.Unwrap(err) != unix.ENOENT {
			log.Error("Error in obtaining next bpf program", zap.Error(err))
			return err
		}

		// We didn't find any ebpf programs
		if bpfProgID.NextId == 0 {
			continue
		}

		bpfProgID.Id = bpfProgID.NextId // set our ID to the program found
		bpfProgID.NextId = 0            // Clear the next ID so we can enumerate all of the BPF programs
		log.Debug("Enumerating the ebpf programs", zap.Any("bpfProgID", bpfProgID))
		for {
			err := sys.ProgGetNextId(bpfProgID)
			log.Debug("Got ebpf programs", zap.Any("bpfProgID", bpfProgID))
			if err != nil && errors.Unwrap(err) != unix.ENOENT {
				log.Error("Unable to obtain ebpf program ID", zap.Error(err))
				return err
			}
			bpfProgFD := &sys.ProgGetFdByIdAttr{Id: bpfProgID.Id}
			fd, err := sys.ProgGetFdById(bpfProgFD)
			if err != nil {
				log.Error("Unable to obtain ebpf program fd", zap.Error(err))
				return err
			}
			var info sys.ProgInfo
			err = sys.ObjInfo(fd, &info)
			if err != nil {
				log.Error("Error in obtaining system object", zap.Error(err))
				return err
			}
			switch ebpf.ProgramType(info.Type) {
			case ebpf.Kprobe, ebpf.TracePoint, ebpf.PerfEvent:
				p := NewProgram(unix.ByteSliceToString(info.Name[:]), info.Id, fd)
				CollectProgramMetrics(p)
			default:
				log.Debug("found different type of bpf program",
					zap.Uint32("type", info.Type),
					zap.String("name", unix.ByteSliceToString(info.Name[:])),
					zap.Uint32("id", info.Id),
				)
			}
			if bpfProgID.NextId == 0 {
				break
			}
			bpfProgID.Id = bpfProgID.NextId // set our ID to the program found
			bpfProgID.NextId = 0            // Clear the next ID so we can enumerate all of the BPF programs
		}
	}
	return nil
}
