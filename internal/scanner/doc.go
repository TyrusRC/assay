// Package scanner provides the core scan orchestration functionality.
//
// The Scanner coordinates multiple security tools to scan targets, collecting
// and deduplicating findings. It supports:
//   - Multiple target URLs
//   - Concurrent tool execution
//   - Finding aggregation and deduplication
//   - Configurable timeouts and concurrency
package scanner
