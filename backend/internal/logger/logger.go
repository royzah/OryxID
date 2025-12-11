// Package logger provides structured logging for the OryxID application.
// It uses Go's standard log/slog package for structured JSON logging.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

var (
	// Default is the default logger instance
	Default *slog.Logger
)

// Config holds logger configuration
type Config struct {
	// Level is the minimum log level (debug, info, warn, error)
	Level string
	// Format is the output format (json, text)
	Format string
	// Output is where logs are written (default: stdout)
	Output io.Writer
}

// Initialize sets up the global logger with the given configuration
func Initialize(cfg Config) {
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}

	level := parseLevel(cfg.Level)

	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: level == slog.LevelDebug,
	}

	if strings.ToLower(cfg.Format) == "text" {
		handler = slog.NewTextHandler(cfg.Output, opts)
	} else {
		handler = slog.NewJSONHandler(cfg.Output, opts)
	}

	Default = slog.New(handler)
	slog.SetDefault(Default)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Helper functions that use the default logger

// Debug logs at debug level
func Debug(msg string, args ...any) {
	Default.Debug(msg, args...)
}

// Info logs at info level
func Info(msg string, args ...any) {
	Default.Info(msg, args...)
}

// Warn logs at warn level
func Warn(msg string, args ...any) {
	Default.Warn(msg, args...)
}

// Error logs at error level
func Error(msg string, args ...any) {
	Default.Error(msg, args...)
}

// DebugContext logs at debug level with context
func DebugContext(ctx context.Context, msg string, args ...any) {
	Default.DebugContext(ctx, msg, args...)
}

// InfoContext logs at info level with context
func InfoContext(ctx context.Context, msg string, args ...any) {
	Default.InfoContext(ctx, msg, args...)
}

// WarnContext logs at warn level with context
func WarnContext(ctx context.Context, msg string, args ...any) {
	Default.WarnContext(ctx, msg, args...)
}

// ErrorContext logs at error level with context
func ErrorContext(ctx context.Context, msg string, args ...any) {
	Default.ErrorContext(ctx, msg, args...)
}

// With returns a new logger with the given attributes
func With(args ...any) *slog.Logger {
	return Default.With(args...)
}

// WithGroup returns a new logger with the given group name
func WithGroup(name string) *slog.Logger {
	return Default.WithGroup(name)
}

// Fatal logs at error level and exits with code 1
func Fatal(msg string, args ...any) {
	Default.Error(msg, args...)
	os.Exit(1)
}

func init() {
	// Initialize with defaults if not explicitly configured
	Initialize(Config{
		Level:  "info",
		Format: "json",
		Output: os.Stdout,
	})
}
