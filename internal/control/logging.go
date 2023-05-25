package control

import (
	"bytes"
	"strings"
)

type LoggingController struct {
	loggers []Logger
}

type LogLevel uint

const (
	LogLevelAll LogLevel = iota
	LogLevelTrace
	LogLevelDebug
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelNone
	LogLevelPanic
	LogLevelFatal
	LogLevelServe
	LogLevelAudit
	LogLevelBoot
)

var DefaultLogLevel = LogLevelInfo

func LogLevelFromString(want string) LogLevel {
	level := DefaultLogLevel
	switch strings.ToLower(want) {
	case `all`:
		level = LogLevelTrace
	case `trace`:
		level = LogLevelTrace
	case `debug`:
		level = LogLevelDebug
	case `info`:
		level = LogLevelInfo
	case `warn`:
		level = LogLevelWarn
	case `error`:
		level = LogLevelError
	case `none`:
		level = LogLevelError
	case `panic`:
		level = LogLevelError
	case `fatal`:
		level = LogLevelError
	case `serve`:
		level = LogLevelError
	case `audit`:
		level = LogLevelError
	case `boot`:
		level = LogLevelError
	}
	return level
}

func (level LogLevel) String() string {
	text := `invalid`
	switch level {
	case LogLevelAll:
		text = `all`
	case LogLevelTrace:
		text = `trace`
	case LogLevelDebug:
		text = `debug`
	case LogLevelInfo:
		text = `info`
	case LogLevelWarn:
		text = `warn`
	case LogLevelError:
		text = `error`
	case LogLevelNone:
		text = `none`
	case LogLevelPanic:
		text = `panic`
	case LogLevelFatal:
		text = `fatal`
	case LogLevelServe:
		text = `serve`
	case LogLevelAudit:
		text = `audit`
	case LogLevelBoot:
		text = `boot`
	}
	return text
}

type Logger interface {
	Level() LogLevel
	SetLevel(LogLevel)
	SetLevelFromString(string)

	Log(LogLevel, string, ...any)

	Trace(string, ...any)
	Debug(string, ...any)
	Info(string, ...any)
	Warn(string, ...any)
	Error(string, ...any)
	Panic(string, ...any)
	Fatal(string, ...any)
	Serve(string, ...any)
	Audit(string, ...any)
}

type HttpLogWriter struct {
	logger Logger
}

func NewHttpLogWriter(logger Logger) HttpLogWriter {
	writer := HttpLogWriter{
		logger: logger,
	}
	return writer
}

func (writer HttpLogWriter) Write(message []byte) (int, error) {
	message = bytes.TrimSpace(message)
	switch {
	case bytes.HasSuffix(message, []byte(`golang.org/issue/25192`)),
		bytes.HasPrefix(message, []byte(`http: TLS handshake error `)):
		writer.logger.Trace(`%s`, string(message))
	default:
		writer.logger.Serve(`%s`, string(message))
	}
	return len(message), nil
}
