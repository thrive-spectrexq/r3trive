// Package plugins implements the Plugin Manager, which loads, configures,
// and communicates with R3TRIVE plugins via gRPC.
//
// See PLUGIN_SDK.md for full specification.
package plugins

// TODO: Implement Plugin Manager:
// - Plugin discovery and loading
// - gRPC server for plugin communication (Unix socket / TCP)
// - Plugin types: input, output, enrichment, action, intelligence
// - Plugin lifecycle management (start, stop, health)
// - Plugin sandboxing (see sandbox/ sub-package)
// - Plugin registry and configuration
