//go:build !windows

package agent

import (
	"context"
	"errors"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// ErrUnsupported is returned on platforms without the Fibratus ETW sensor.
var ErrUnsupported = errors.New("agent: Fibratus sensor is only supported on Windows")

// Handlers mirrors the Windows API.
type Handlers struct {
	OnEvent func(*event.Event)
	OnAlert func(*config.FilterConfig, ...*event.Event)
	OnError func(error)
}

// Agent is a non-Windows stub.
type Agent struct{}

// New returns ErrUnsupported on non-Windows platforms.
func New(Config, Handlers) (*Agent, error) { return nil, ErrUnsupported }

// Run returns ErrUnsupported.
func (*Agent) Run(context.Context) error { return ErrUnsupported }

// Close is a no-op.
func (*Agent) Close() error { return nil }
