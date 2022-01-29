package core

import (
	"fmt"
	"github.com/fatih/color"
	"regexp"
	"strings"
	"sync"
)

const (
	FATAL     = 5
	ERROR     = 4
	IMPORTANT = 3
	WARN      = 2
	INFO      = 1
	DEBUG     = 0
)

var LogColors = map[int]*color.Color{
	FATAL:     color.New(color.FgRed).Add(color.Bold),
	ERROR:     color.New(color.FgRed),
	IMPORTANT: color.New(color.FgMagenta),
	WARN:      color.New(color.FgYellow),
	INFO:      color.New(),
	DEBUG:     color.New(color.Faint),
}

type Logger struct {
	sync.Mutex

	debugLevel int
}

func (l *Logger) SetDebugLevel(d string) {
	l.debugLevel = ERROR

	if strings.EqualFold(d, "FATAL") {
		l.debugLevel = FATAL
	} else if strings.EqualFold(d, "ERROR") {
		l.debugLevel = ERROR
	} else if strings.EqualFold(d, "IMPORTANT") {
		l.debugLevel = IMPORTANT
	} else if strings.EqualFold(d, "WARN") {
		l.debugLevel = WARN
	} else if strings.EqualFold(d, "INFO") {
		l.debugLevel = INFO
	} else if strings.EqualFold(d, "DEBUG") {
		l.debugLevel = DEBUG
	}
}

func (l *Logger) Log(level int, format string, args ...interface{}) {
	l.Lock()
	defer l.Unlock()

	if level < l.debugLevel {
		return
	}

	if c, ok := LogColors[level]; ok {
		c.Printf("\r"+format+"\n", args...)
	} else {
		fmt.Printf("\r"+format+"\n", args...)
	}

	if level == FATAL {
		panic("Fatal error....")
	}
}

func (l *Logger) Fatal(format string, args ...interface{}) {
	l.Log(FATAL, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.Log(ERROR, format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.Log(WARN, format, args...)
}

func (l *Logger) Important(format string, args ...interface{}) {
	l.Log(IMPORTANT, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.Log(INFO, format, args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.Log(DEBUG, format, args...)
}

func colorStrip(str string) string {
	ansi := "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
	re := regexp.MustCompile(ansi)
	return re.ReplaceAllString(str, "")
}
