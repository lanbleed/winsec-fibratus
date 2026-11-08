//go:build !windows

package agent

import "time"

// Config mirrors the Windows configuration surface for API compatibility.
// The sensor itself is Windows-only.
type Config struct {
	RulesPath            string
	EnableThreadEvents   bool
	EnableRegistryEvents bool
	EnableNetEvents      bool
	EnableFileIOEvents   bool
	EnableVAMapEvents    bool
	EnableModuleEvents   bool
	EnableMemEvents      bool
	EnableAuditAPIEvents bool
	EnableDNSEvents      bool
	StackEnrichment      bool
	BufferSize           uint32
	MinBuffers           uint32
	MaxBuffers           uint32
	FlushTimer           time.Duration
	InitHandleSnapshot   bool
	EnumerateHandles     bool
}

// DefaultConfig returns a zero configuration on non-Windows platforms.
func DefaultConfig() Config { return Config{} }
