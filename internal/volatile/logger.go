package volatile

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

type LogLevel uint

const (
	LogLevelAll LogLevel = iota
	LogLevelTrace
	LogLevelDebug
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelNone
)

type Logger struct {
	level    LogLevel
	prefixes []string
}

func NewLogger(level LogLevel) *Logger {
	logger := &Logger{
		level:    level,
		prefixes: []string{},
	}
	return logger
}

func (logger Logger) Log(level string, format string, args ...any) {
	fmt.Println(time.Now().UTC().Format(`2006-01-02 15:04:05`) + fmt.Sprintf(` [%-5s] `, level) + fmt.Sprintf(format, args...))
}

func (logger *Logger) SetLevel(level LogLevel) {
	logger.level = level
}

func (logger *Logger) Trim(prefix string) {
	logger.prefixes = append(logger.prefixes, prefix)
}

func (logger *Logger) SetLevelFromString(want string) error {
	switch strings.ToLower(want) {
	case `all`:
		logger.level = LogLevelAll
	case `trace`:
		logger.level = LogLevelTrace
	case `debug`:
		logger.level = LogLevelDebug
	case `info`:
		logger.level = LogLevelInfo
	case `warn`:
		logger.level = LogLevelWarn
	case `error`:
		logger.level = LogLevelError
	case `none`:
		logger.level = LogLevelNone
	default:
		return fmt.Errorf(`level "%s" is invalid`, want)
	}
	return nil
}

func (logger Logger) Trace(format string, args ...any) {
	if logger.level <= LogLevelTrace {
		logger.Log(`trace`, format, args...)
	}
}

func (logger Logger) Debug(format string, args ...any) {
	if logger.level <= LogLevelDebug {
		logger.Log(`debug`, format, args...)
	}
}

func (logger Logger) Info(format string, args ...any) {
	if logger.level <= LogLevelInfo {
		logger.Log(`info`, format, args...)
	}
}

func (logger Logger) Warn(format string, args ...any) {
	if logger.level <= LogLevelWarn {
		logger.Log(`warn`, format, args...)
	}
}

func (logger Logger) Error(format string, args ...any) {
	if logger.level <= LogLevelError {
		logger.Log(`error`, format, args...)
	}
}

func (logger Logger) Audit(format string, args ...any) {
	logger.Log(`audit`, format, args...)
}

func (logger Logger) Fatal(format string, args ...any) {
	logger.Log(`fatal`, format, args...)
	os.Exit(1)
}

type LogFormatter struct {
	label  string
	logger *Logger
}

var _ middleware.LogFormatter = (*LogFormatter)(nil)

func NewLogFormatter(label string, logger *Logger) LogFormatter {
	formatter := LogFormatter{
		label:  label,
		logger: logger,
	}
	return formatter
}

func (formatter LogFormatter) NewLogEntry(r *http.Request) middleware.LogEntry {
	return LogEntry{LogFormatter: formatter, request: r}
}

type LogEntry struct {
	LogFormatter
	request *http.Request
}

var _ middleware.LogEntry = (*LogEntry)(nil)

func (entry LogEntry) Write(code int, written int, header http.Header, elapsed time.Duration, extra any) {
	req := entry.request
	for _, prefix := range entry.logger.prefixes {
		if strings.HasPrefix(req.RequestURI, prefix) {
			return
		}
	}
	entry.logger.Log(`serve`, `%-5s %s %d %-7s %-21s %9d %15s %s`,
		entry.label, middleware.GetReqID(req.Context()), code, req.Method, req.RemoteAddr, written, elapsed.String(), req.RequestURI)
}

func (entry LogEntry) Panic(v any, stack []byte) {
	entry.logger.Log(`panic`, `%T %+v %s`, v, v, string(stack))
}
