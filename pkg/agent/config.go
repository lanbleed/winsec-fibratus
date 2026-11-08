//go:build windows

package agent

import (
	"runtime"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/ps"
)

// Config is the minimal configuration surface for the embedded Fibratus
// sensor. It deliberately does not expose Fibratus' output, alert-sender,
// aggregator or filament configuration: those are app-shell concerns and are
// provided by the host agent (hub, agentwire, OpenSearch, ...).
type Config struct {
	// RulesPath is a glob of Fibratus rule files. Empty disables the rule
	// engine (capture + process state only).
	RulesPath string

	// EnableThreadEvents, EnableRegistryEvents, ... control which kernel
	// event classes are captured. All default to true in DefaultConfig.
	EnableThreadEvents   bool
	EnableRegistryEvents bool
	EnableNetEvents      bool
	EnableFileIOEvents   bool
	EnableVAMapEvents    bool
	EnableModuleEvents   bool
	EnableMemEvents      bool
	EnableAuditAPIEvents bool
	EnableDNSEvents      bool

	// StackEnrichment enables callstack resolution for eligible events.
	StackEnrichment bool
	// BufferSize is the ETW buffer size in kilobytes; 0 uses 512.
	BufferSize uint32
	// MinBuffers/MaxBuffers bound the trace buffer pool; 0 uses CPU-derived
	// defaults.
	MinBuffers uint32
	MaxBuffers uint32
	// FlushTimer is the ETW flush interval; 0 uses 1s.
	FlushTimer time.Duration
	// InitHandleSnapshot/EnumerateHandles control the handle snapshotter.
	InitHandleSnapshot bool
	EnumerateHandles   bool
}

// DefaultConfig returns a full-sensor configuration with all kernel event
// classes enabled and the usual process/handle enrichment.
func DefaultConfig() Config {
	return Config{
		EnableThreadEvents:   true,
		EnableRegistryEvents: true,
		EnableNetEvents:      true,
		EnableFileIOEvents:   true,
		EnableVAMapEvents:    true,
		EnableModuleEvents:   true,
		EnableMemEvents:      true,
		EnableAuditAPIEvents: true,
		EnableDNSEvents:      true,
		StackEnrichment:      true,
		BufferSize:           512,
		MinBuffers:           uint32(runtime.NumCPU() * 2),
		MaxBuffers:           uint32(runtime.NumCPU() * 8),
		FlushTimer:           time.Second,
		InitHandleSnapshot:   true,
		EnumerateHandles:     true,
	}
}

// toFibratusConfig maps the public agent config onto Fibratus' internal
// configuration. This is intentionally the only place that knows about the
// upstream config type.
func (c Config) toFibratusConfig() *config.Config {
	es := config.EventSourceConfig{
		EnableThreadEvents:   c.EnableThreadEvents,
		EnableRegistryEvents: c.EnableRegistryEvents,
		EnableNetEvents:      c.EnableNetEvents,
		EnableFileIOEvents:   c.EnableFileIOEvents,
		EnableVAMapEvents:    c.EnableVAMapEvents,
		EnableModuleEvents:   c.EnableModuleEvents,
		EnableMemEvents:      c.EnableMemEvents,
		EnableAuditAPIEvents: c.EnableAuditAPIEvents,
		EnableDNSEvents:      c.EnableDNSEvents,
		StackEnrichment:      c.StackEnrichment,
		BufferSize:           c.BufferSize,
		MinBuffers:           c.MinBuffers,
		MaxBuffers:           c.MaxBuffers,
		FlushTimer:           c.FlushTimer,
	}
	es.Init()

	filters := &config.Filters{}
	if c.RulesPath != "" {
		filters.Rules = config.Rules{Enabled: true, FromPaths: []string{c.RulesPath}}
	}

	return &config.Config{
		BaseConfig: config.BaseConfig{
			EventSource: es,
			Filters:     filters,
		},
		PE:                 pe.Config{},
		InitHandleSnapshot: c.InitHandleSnapshot,
		EnumerateHandles:   c.EnumerateHandles,
	}
}

// newSnapshotter builds the Fibratus process/handle state. It is a var so the
// agent tests can substitute a fake without a live Windows host.
var newSnapshotter = func(cfg *config.Config) (ps.Snapshotter, handle.Snapshotter) {
	hsnap := handle.NewSnapshotter(cfg, nil)
	psnap := ps.NewSnapshotter(hsnap, cfg)
	return psnap, hsnap
}
