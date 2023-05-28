package volatile

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"ultra/internal/control"
)

type Logger struct {
	level control.LogLevel
}

var _ control.Logger = (*Logger)(nil)

func NewLogger(level control.LogLevel) *Logger {
	logger := &Logger{
		level: level,
	}
	return logger
}

func (logger Logger) Log(level control.LogLevel, format string, args ...any) {
	fmt.Println(time.Now().UTC().Format(`2006-01-02 15:04:05`) + fmt.Sprintf(` [%-5s] `, level.String()) + fmt.Sprintf(format, args...))
}

func (logger *Logger) Level() control.LogLevel {
	return logger.level
}

func (logger *Logger) SetLevel(level control.LogLevel) {
	logger.level = level
}

func (logger *Logger) SetLevelFromString(want string) {
	logger.level = control.LogLevelFromString(want)
}

func (logger Logger) Trace(format string, args ...any) {
	if logger.level <= control.LogLevelTrace {
		logger.Log(control.LogLevelTrace, format, args...)
	}
}

func (logger Logger) Debug(format string, args ...any) {
	if logger.level <= control.LogLevelDebug {
		logger.Log(control.LogLevelDebug, format, args...)
	}
}

func (logger Logger) Info(format string, args ...any) {
	if logger.level <= control.LogLevelInfo {
		logger.Log(control.LogLevelInfo, format, args...)
	}
}

func (logger Logger) Warn(format string, args ...any) {
	if logger.level <= control.LogLevelWarn {
		logger.Log(control.LogLevelWarn, format, args...)
	}
}

func (logger Logger) Error(format string, args ...any) {
	if logger.level <= control.LogLevelError {
		logger.Log(control.LogLevelError, format, args...)
	}
}

func (logger Logger) Panic(format string, args ...any) {
	logger.Log(control.LogLevelPanic, format, args...)
}

func (logger Logger) Fatal(format string, args ...any) {
	logger.Log(control.LogLevelFatal, format, args...)
	os.Exit(1)
}

func (logger Logger) Serve(format string, args ...any) {
	logger.Log(control.LogLevelServe, format, args...)
}

func (logger Logger) Audit(format string, args ...any) {
	logger.Log(control.LogLevelAudit, format, args...)
}

func (logger Logger) Help(format string, args ...any) {
	logger.Log(control.LogLevelHelp, format, args...)
}

type LogFormatter struct {
	label  string
	logger control.Logger
}

var _ middleware.LogFormatter = (*LogFormatter)(nil)

func NewLogFormatter(label string, logger control.Logger) LogFormatter {
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
	sig := '.'
	if req.TLS != nil {
		sig = '^'
	}
	// FIXME: there are 3 slots left to move the path to the correct column
	// FIXME: need stripped path here? what is correct through the entire cycle?
	entry.logger.Serve(`%-5s %c %s %d %-7s %-21s %9d %9d %15s    %s`,
		entry.label, sig, middleware.GetReqID(req.Context()),
		code, req.Method, req.RemoteAddr, req.ContentLength, written, elapsed.String(), req.URL.String())
}

func (entry LogEntry) Panic(v any, stack []byte) {
	entry.logger.Panic(`%T %+v %s`, v, v, string(stack))
}
