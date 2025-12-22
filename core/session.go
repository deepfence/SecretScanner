package core

import (
	"context"
	"os"
	"runtime"
	"sync"

	"github.com/deepfence/match-scanner/pkg/config"
	"github.com/rs/zerolog/log"
)

type Session struct {
	sync.Mutex
	Version         string
	Options         *Options
	Config          *Config
	Context         context.Context
	ExtractorConfig config.Config
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
			log.Error().Err(err).Msg("failed to parse options")
			os.Exit(1)
		}

		if session.ExtractorConfig, err = loadExtractorConfigFile(session.Options); err != nil {
			log.Error().Err(err).Msg("failed to load extractor config")
			os.Exit(1)
		}

		session.Start()
	})

	return session
}
