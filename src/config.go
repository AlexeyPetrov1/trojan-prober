package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/liuylv/trojan-prober/src/log"
)

// Config holds runtime options.
type Config struct {
	Probe               string
	TargetServer        string
	TargetPort          string
	ServerAddr          string
	LogLevel            int
	PredictionMode      PredictionMode
	IncludeH1Incomplete bool
	StopOnDetected      bool
	ProbeTimeout        time.Duration
	FinTimeout          time.Duration
	OverbufferTimeout   time.Duration
	IncompleteTimeout   time.Duration
	OverbufferRepeatNum int
	Retries             int
	DelayBetweenProbes  time.Duration
	OutputFormat        string
	OutputPath          string
}

func parseConfig() Config {
	var cfg Config
	var predictionMode string
	var includeH1Incomplete bool
	var stopOnDetected bool

	flag.StringVar(&cfg.Probe, "probe", "", "Probe name or 'all' (required)")
	flag.StringVar(&cfg.TargetServer, "targetServer", "", "Target server IP or hostname (required)")
	flag.StringVar(&cfg.TargetPort, "targetPort", "", "Target server port (required)")
	flag.IntVar(&cfg.LogLevel, "log", 1, "Log level: 0 for all logs, 1 for crucial logs only")
	flag.StringVar(&predictionMode, "prediction-mode", "specific", "Final verdict mode: specific|any-trojan")
	flag.BoolVar(&includeH1Incomplete, "include-h1-incomplete", false, "Include H1-Incomplete probe in --probe all")
	flag.BoolVar(&stopOnDetected, "stop-on-detected", false, "Stop --probe all after decisive DETECTED")
	flag.DurationVar(&cfg.ProbeTimeout, "probe-timeout", 30*time.Second, "Per-probe TLS/read timeout")
	flag.DurationVar(&cfg.FinTimeout, "fin-timeout", 45*time.Second, "FIN capture timeout for H1-Close/H1-Incomplete")
	flag.DurationVar(&cfg.OverbufferTimeout, "overbuffer-timeout", 20*time.Second, "Overbuffer-Incomplete wait timeout")
	flag.DurationVar(&cfg.IncompleteTimeout, "incomplete-timeout", 605*time.Second, "H1-Incomplete total wait timeout")
	flag.IntVar(&cfg.OverbufferRepeatNum, "overbuffer-repeat-num", 0, "Override repeat_num in Overbuffer JSON (0 = use JSON)")
	flag.IntVar(&cfg.Retries, "retries", 1, "Retries per probe")
	flag.DurationVar(&cfg.DelayBetweenProbes, "delay-between-probes", 5*time.Second, "Delay between probes in --probe all")
	flag.StringVar(&cfg.OutputFormat, "format", "text", "Output format: text|json")
	flag.StringVar(&cfg.OutputPath, "output", "", "Write JSON report to file")

	flag.Parse()
	log.SetLogLevel(cfg.LogLevel)

	if cfg.Probe == "" || cfg.TargetServer == "" || cfg.TargetPort == "" {
		fmt.Println("Usage of trojan-prober:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	switch PredictionMode(predictionMode) {
	case PredictionSpecific, PredictionAnyTrojan:
		cfg.PredictionMode = PredictionMode(predictionMode)
	default:
		fmt.Fprintf(os.Stderr, "invalid --prediction-mode: %s (use specific or any-trojan)\n", predictionMode)
		os.Exit(1)
	}

	cfg.IncludeH1Incomplete = includeH1Incomplete
	cfg.StopOnDetected = stopOnDetected
	cfg.ServerAddr = net.JoinHostPort(cfg.TargetServer, cfg.TargetPort)

	if cfg.OutputFormat != "text" && cfg.OutputFormat != "json" {
		fmt.Fprintf(os.Stderr, "invalid --format: %s (use text or json)\n", cfg.OutputFormat)
		os.Exit(1)
	}

	return cfg
}

func buildProbeSet(cfg Config) []string {
	if cfg.Probe != "all" {
		return []string{cfg.Probe}
	}
	probes := []string{
		"H1-Close",
		"Overbuffer-Incomplete",
		"Short-ALPN-h2",
		"H1-ALPN-h2",
	}
	if cfg.IncludeH1Incomplete {
		probes = append(probes, "H1-Incomplete")
	}
	return probes
}
