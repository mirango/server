// Copyright (c) 2014 Tyler Bunnell
package server

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/mirango/framework"

	"golang.org/x/net/netutil"
)

type Server struct {
	*http.Server
	Timeout           time.Duration
	ListenLimit       int
	ConnState         func(net.Conn, http.ConnState)
	BeforeShutdown    func()
	ShutdownInitiated func()
	NoSignalHandling  bool
	Logger            framework.LogWriter
	Interrupted       bool
	interrupt         chan os.Signal
	stopLock          sync.Mutex
	stopChan          chan struct{}
	chanLock          sync.RWMutex
	connections       map[net.Conn]struct{}
}

func New() *Server {
	return &Server{
		Server: &http.Server{},
	}
}

func (srv *Server) ListenAndServe() error {
	// Create the listener so we can control their lifetime
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return srv.Serve(l)
}

func (srv *Server) SetHandler(h http.Handler) {
	srv.Handler = h
}

func (srv *Server) SetAddr(addr string) {
	srv.Addr = addr
}

func (srv *Server) SetLogger(logger framework.LogWriter) {
	srv.Logger = logger
}

func (srv *Server) ListenTLS(certFile, keyFile string) (net.Listener, error) {
	// Create the listener ourselves so we can control its lifetime
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	config := &tls.Config{}
	if srv.TLSConfig != nil {
		*config = *srv.TLSConfig
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	conn, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsListener := tls.NewListener(conn, config)
	return tlsListener, nil
}

func (srv *Server) ListenAndServeTLS(certFile, keyFile string) error {
	l, err := srv.ListenTLS(certFile, keyFile)
	if err != nil {
		return err
	}

	return srv.Serve(l)
}

func (srv *Server) ListenAndServeTLSConfig(config *tls.Config) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	conn, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	tlsListener := tls.NewListener(conn, config)
	return srv.Serve(tlsListener)
}

func (srv *Server) Serve(listener net.Listener) error {

	if srv.ListenLimit != 0 {
		listener = netutil.LimitListener(listener, srv.ListenLimit)
	}

	// Track connection state
	add := make(chan net.Conn)
	remove := make(chan net.Conn)

	srv.Server.ConnState = func(conn net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			add <- conn
		case http.StateClosed, http.StateHijacked:
			remove <- conn
		}
		if srv.ConnState != nil {
			srv.ConnState(conn, state)
		}
	}

	// Manage open connections
	shutdown := make(chan chan struct{})
	kill := make(chan struct{})
	go srv.manageConnections(add, remove, shutdown, kill)

	interrupt := srv.interruptChan()
	// Set up the interrupt handler
	if !srv.NoSignalHandling {
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	}
	quitting := make(chan struct{})
	go srv.handleInterrupt(interrupt, quitting, listener)

	// Serve with graceful listener.
	// Execution blocks here until listener.Close() is called, above.
	err := srv.Server.Serve(listener)
	if err != nil {
		// If the underlying listening is closed, Serve returns an error
		// complaining about listening on a closed socket. This is expected, so
		// let's ignore the error if we are the ones who explicitly closed the
		// socket.
		select {
		case <-quitting:
			err = nil
		default:
		}
	}

	srv.shutdown(shutdown, kill)

	return err
}

func (srv *Server) Stop(timeout time.Duration) {
	srv.stopLock.Lock()
	defer srv.stopLock.Unlock()

	srv.Timeout = timeout
	interrupt := srv.interruptChan()
	interrupt <- syscall.SIGINT
}

func (srv *Server) StopChan() <-chan struct{} {
	srv.chanLock.Lock()
	defer srv.chanLock.Unlock()

	if srv.stopChan == nil {
		srv.stopChan = make(chan struct{})
	}
	return srv.stopChan
}

func (srv *Server) manageConnections(add, remove chan net.Conn, shutdown chan chan struct{}, kill chan struct{}) {
	var done chan struct{}
	srv.connections = map[net.Conn]struct{}{}
	for {
		select {
		case conn := <-add:
			srv.connections[conn] = struct{}{}
		case conn := <-remove:
			delete(srv.connections, conn)
			if done != nil && len(srv.connections) == 0 {
				done <- struct{}{}
				return
			}
		case done = <-shutdown:
			if len(srv.connections) == 0 {
				done <- struct{}{}
				return
			}
		case <-kill:
			for k := range srv.connections {
				if err := k.Close(); err != nil {
					srv.log("[ERROR] %s", err)
				}
			}
			return
		}
	}
}

func (srv *Server) interruptChan() chan os.Signal {
	srv.chanLock.Lock()
	defer srv.chanLock.Unlock()

	if srv.interrupt == nil {
		srv.interrupt = make(chan os.Signal, 1)
	}

	return srv.interrupt
}

func (srv *Server) handleInterrupt(interrupt chan os.Signal, quitting chan struct{}, listener net.Listener) {
	for _ = range interrupt {
		if srv.Interrupted {
			srv.log("already shutting down")
			continue
		}
		srv.log("shutdown initiated")
		srv.Interrupted = true
		if srv.BeforeShutdown != nil {
			srv.BeforeShutdown()
		}

		close(quitting)
		srv.SetKeepAlivesEnabled(false)
		if err := listener.Close(); err != nil {
			srv.log("[ERROR] %s", err)
		}

		if srv.ShutdownInitiated != nil {
			srv.ShutdownInitiated()
		}
	}
}

func (srv *Server) log(fmt string, v ...interface{}) {
	if srv.Logger != nil {
		srv.Logger.Print(fmt, v...)
	}
}

func (srv *Server) shutdown(shutdown chan chan struct{}, kill chan struct{}) {
	// Request done notification
	done := make(chan struct{})
	shutdown <- done

	if srv.Timeout > 0 {
		select {
		case <-done:
		case <-time.After(srv.Timeout):
			close(kill)
		}
	} else {
		<-done
	}
	// Close the stopChan to wake up any blocked goroutines.
	srv.chanLock.Lock()
	if srv.stopChan != nil {
		close(srv.stopChan)
	}
	srv.chanLock.Unlock()
}
