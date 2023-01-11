package cmd

import (
	"fmt"
	"os"

	"github.com/levigross/ebpf-metrics/pkg/metrics"
	"github.com/levigross/logger/logger"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var (
	cfg  metrics.Config
	opts logger.Options
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ebpf-metrics",
	Short: "An exporter for ebpf and perf metrics",
	Long:  ``,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if unix.Getuid() != 0 {
			return fmt.Errorf("%s must be run as root ", cmd.Name())
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		logger.Hydrate(logger.New(logger.UseFlagOptions(&opts)))
		return cfg.Run()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolVar(&cfg.EnableBPFMetrics, "enable-ebpf-metrics", true, "Try and enable ebpf metrics")
	rootCmd.Flags().BoolVar(&cfg.DisableMetricsOnShutdown, "cleanup-on-shutdown", true, "Disable ebpf metrics when we close gracefully")
	rootCmd.Flags().Uint16Var(&cfg.Port, "metrics-port", 2312, "The port to use for prometheus metrics")
	opts.BindFlags(rootCmd.Flags())
}
