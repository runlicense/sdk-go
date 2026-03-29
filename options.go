package runlicense

import "log/slog"

// Option configures the behavior of Activate functions.
type Option func(*options)

type options struct {
	logger *slog.Logger
}

func defaults() *options {
	return &options{}
}

func applyOptions(opts []Option) *options {
	o := defaults()
	for _, fn := range opts {
		fn(o)
	}
	return o
}

// WithLogger enables verbose logging using the provided slog.Logger.
// When set, the SDK logs each step of the license verification pipeline,
// including file discovery, signature verification, status checks, and
// phone-home validation.
//
// Example:
//
//	result, err := runlicense.Activate(ctx, "acme/pkg", publicKey,
//	    runlicense.WithLogger(slog.Default()),
//	)
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		o.logger = l
	}
}

// logDebug logs a message at debug level if logging is enabled.
func (o *options) logDebug(msg string, args ...any) {
	if o.logger != nil {
		o.logger.Debug(msg, args...)
	}
}

// logInfo logs a message at info level if logging is enabled.
func (o *options) logInfo(msg string, args ...any) {
	if o.logger != nil {
		o.logger.Info(msg, args...)
	}
}

// logWarn logs a message at warn level if logging is enabled.
func (o *options) logWarn(msg string, args ...any) {
	if o.logger != nil {
		o.logger.Warn(msg, args...)
	}
}
