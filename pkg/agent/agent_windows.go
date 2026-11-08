//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/rabbitstack/fibratus/internal/etw"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/rules"
	"github.com/rabbitstack/fibratus/pkg/source"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	log "github.com/sirupsen/logrus"
)

// Handlers are the host-agent callbacks. They must not block the capture
// pipeline; a slow handler belongs on its own queue.
type Handlers struct {
	// OnEvent receives every event after process-state enrichment.
	OnEvent func(*event.Event)
	// OnAlert receives a rule match (the rule config and the matched events).
	OnAlert func(*config.FilterConfig, ...*event.Event)
	// OnError receives non-fatal capture/enrichment errors.
	OnError func(error)
}

// Agent is a running embedded Fibratus sensor.
type Agent struct {
	cfg    Config
	h      Handlers
	engine *rules.Engine
	src    source.EventSource
	fcfg   *config.Config
	once   sync.Once
}

// New validates the configuration and builds the engine/source. It does not
// start capture; call Run for that.
func New(cfg Config, h Handlers) (*Agent, error) {
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 512
	}
	if cfg.MinBuffers == 0 || cfg.MaxBuffers == 0 || cfg.FlushTimer == 0 {
		d := DefaultConfig()
		if cfg.MinBuffers == 0 {
			cfg.MinBuffers = d.MinBuffers
		}
		if cfg.MaxBuffers == 0 {
			cfg.MaxBuffers = d.MaxBuffers
		}
		if cfg.FlushTimer == 0 {
			cfg.FlushTimer = d.FlushTimer
		}
	}
	fcfg := cfg.toFibratusConfig()

	signature.InitStore()
	fs.InitMetadataStore()

	psnap, hsnap := newSnapshotter(fcfg)

	var engine *rules.Engine
	var compileResult *config.RulesCompileResult
	if fcfg.Filters != nil && fcfg.Filters.Rules.Enabled {
		engine = rules.NewEngine(psnap, fcfg)
		var err error
		compileResult, err = engine.Compile()
		if err != nil {
			return nil, fmt.Errorf("agent: compile rules: %w", err)
		}
	}
	if engine != nil && h.OnAlert != nil {
		engine.RegisterMatchFunc(h.OnAlert)
	}

	src := etw.NewEventSource(psnap, hsnap, fcfg, compileResult)
	return &Agent{cfg: cfg, h: h, engine: engine, src: src, fcfg: fcfg}, nil
}

// Run starts the ETW capture and blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.src.Open(a.fcfg); err != nil {
		return fmt.Errorf("agent: open event source: %w", err)
	}
	defer a.close()

	go func() {
		for err := range a.src.Errors() {
			if err == nil {
				continue
			}
			if a.h.OnError != nil {
				a.h.OnError(err)
				continue
			}
			log.WithError(err).Warn("agent: capture error")
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-a.src.Events():
			if !ok {
				return nil
			}
			if ev == nil {
				continue
			}
			if a.h.OnEvent != nil {
				a.h.OnEvent(ev)
			}
			if a.engine != nil {
				if _, err := a.engine.ProcessEvent(ev); err != nil {
					// Alerts are delivered through OnAlert; a rule-processing
					// error must not stop the capture loop.
					log.WithError(err).Warn("agent: rule engine process event")
				}
			}
		}
	}
}

// Close stops the sensor. Safe to call more than once.
func (a *Agent) Close() error { return a.close() }

func (a *Agent) close() error {
	var err error
	a.once.Do(func() {
		err = a.src.Close()
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
