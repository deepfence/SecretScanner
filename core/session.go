package core

import (
	"context"
	"os"
	"runtime"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

type Session struct {
	sync.Mutex
	Version string
	Options *Options
	Config  *Config
	Context context.Context
}

var (
	session     *Session
	sessionSync sync.Once
	err         error
)

func (s *Session) Start() {
	s.InitThreads()
}

func (s *Session) InitThreads() {
	if *s.Options.Threads == 0 {
		numCPUs := runtime.NumCPU()
		s.Options.Threads = &numCPUs
	}

	runtime.GOMAXPROCS(*s.Options.Threads + 1)
}

func GetSession() *Session {
	sessionSync.Do(func() {
		session = &Session{
			Context: context.Background(),
		}

		if session.Options, err = ParseOptions(); err != nil {
			log.Error(err)
			os.Exit(1)
		}

		if session.Config, err = ParseConfig(session.Options); err != nil {
			log.Error(err)
			os.Exit(1)
		}

		pathSeparator := string(os.PathSeparator)
		nameSeperator := "-"
		var blacklistedPaths []string
		for _, blacklistedPath := range session.Config.BlacklistedPaths {
			blacklistedPaths = append(blacklistedPaths, strings.ReplaceAll(blacklistedPath, "{sep}", pathSeparator))
		}
		session.Config.BlacklistedPaths = blacklistedPaths
		var excludePaths []string
		for _, excludePath := range session.Config.ExcludePaths {
			excludePaths = append(excludePaths, strings.ReplaceAll(excludePath, "{sep}", pathSeparator))
			excludePaths = append(excludePaths, strings.ReplaceAll(excludePath, "{name_sep}", nameSeperator))

		}
		session.Config.ExcludePaths = excludePaths

		session.Start()
	})

	return session
}
