package core

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"time"
)

type Session struct {
	sync.Mutex
	Version   string
	Options   *Options
	Config    *Config
	Context   context.Context
	Log              *Logger
}

var (
	session     *Session
	sessionSync sync.Once
	err         error
)

func (s *Session) Start() {
	rand.Seed(time.Now().Unix())

	s.InitLogger()
	s.InitThreads()
}

func (s *Session) InitLogger() {
	s.Log = &Logger{}
	s.Log.SetDebugLevel(*s.Options.DebugLevel)
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
		fmt.Println("Initializing....")
		session = &Session{
			Context: context.Background(),
		}

		if session.Options, err = ParseOptions(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if session.Config, err = ParseConfig(session.Options); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		session.Start()
	})

	return session
}
