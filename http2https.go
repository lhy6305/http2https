package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// --- CONFIGURATION ---
const (
	targetURL  = "http://127.0.0.1:3004"
	listenAddr = "0.0.0.0:3005"
	certFile   = "cert.pem"
	keyFile    = "key.pem"
)

// currentLogLevel controls the verbosity of the logs.
// Change this value to LogLevelDebug, LogLevelInfo, or LogLevelError
const currentLogLevel = "info" // <--- 在这里修改日志等级

func init_zlogger() {
	outputTemplate := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	outputTemplate.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("|%-5s|", i))
	}
	outputTemplate.FormatMessage = func(i interface{}) string {
		return fmt.Sprintf("%s", i)
	}
	outputTemplate.FormatFieldName = func(i interface{}) string {
		return fmt.Sprintf("%s:", i)
	}
	outputTemplate.FormatFieldValue = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("%s", i))
	}
	fileLogger := &lumberjack.Logger{
		Filename:   "http2https.log",
		MaxSize:    10,   // megabytes
		MaxBackups: 3,    // 最多保留3个备份
		MaxAge:     7,    // days
		Compress:   true, // 压缩旧文件
	}

	colorableStdout := colorable.NewColorableStdout()

	consoleWriter := outputTemplate
	consoleWriter.NoColor = false
	consoleWriter.Out = zerolog.SyncWriter(colorableStdout)

	fileWriter := outputTemplate
	fileWriter.NoColor = true
	fileWriter.Out = zerolog.SyncWriter(fileLogger)

	multiWriter := zerolog.MultiLevelWriter(consoleWriter, fileWriter)

	level, err := zerolog.ParseLevel(currentLogLevel)
	if err != nil {
		zlog.Warn().Msgf("invalid log level '%s'. falling back to 'info'", currentLogLevel)
		level = zerolog.InfoLevel
	}

	logger := zerolog.New(multiWriter).
		Level(level).
		With().
		Timestamp().
		Logger()

	zlog.Logger = logger
}

// bufConn is a net.Conn that allows peeking at the initial bytes of a connection.
// It's used to pass the already-buffered data to the TLS handshake.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// chanListener is a net.Listener that accepts connections from a channel.
// This allows us to feed connections manually into an http.Server.
type chanListener struct {
	connCh chan net.Conn
	addr   net.Addr
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{
		connCh: make(chan net.Conn, 65536),
		addr:   addr,
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	conn, ok := <-l.connCh
	if !ok {
		return nil, errors.New("listener closed")
	}
	return conn, nil
}

func (l *chanListener) Close() error {
	close(l.connCh)
	return nil
}

func (l *chanListener) Addr() net.Addr {
	return l.addr
}

func main() {
	init_zlogger()

	target, err := url.Parse(targetURL)
	if err != nil {
		zlog.Fatal().Err(err).Msgf("Failed to parse target URL %s", targetURL)
	}
	zlog.Info().Msgf("Reverse proxy targeting %s", targetURL)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			// httputil.ReverseProxy will handle this for us
			//clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
			//if err != nil {
			//	clientIP = req.RemoteAddr
			//}
			//if prior, ok := req.Header["X-Forwarded-For"]; ok {
			//	clientIP = strings.Join(prior, ", ") + ", " + clientIP
			//}
			//req.Header.Set("X-Forwarded-For", clientIP)
		},
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true, // prefer http/2
			MaxIdleConns:          65536,
			MaxIdleConnsPerHost:   1024,
			MaxConnsPerHost:       1024,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   3 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if err != context.Canceled {
				zlog.Error().Err(err).Str("client_addr", r.RemoteAddr).Msg("Proxy error")
			}
			if r.Context().Err() == nil {
				http.Error(w, "Proxy Error", http.StatusBadGateway)
			}
		},
	}

	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Forwarded-Host", r.Host)
		r.Header.Set("X-Forwarded-Proto", "https")
		zlog.Debug().Str("client_addr", r.RemoteAddr).Str("method", r.Method).Str("path", r.URL.Path).Msg("Proxying request")
		proxy.ServeHTTP(w, r)
	})

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		zlog.Fatal().Err(err).Msgf("Failed to load cert/key pair from %s and %s", certFile, keyFile)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		zlog.Fatal().Err(err).Msgf("Failed to listen on %s", listenAddr)
	}
	defer listener.Close()

	// Create a single HTTP server for all HTTPS connections
	httpServerLogger := zlog.Logger.With().Str("component", "http_server").Str("level", "ERROR").Logger()
	httpsListener := newChanListener(listener.Addr())
	httpsServer := &http.Server{
		Handler:           proxyHandler,
		ReadTimeout:       120 * time.Second,
		WriteTimeout:      300 * time.Second,
		IdleTimeout:       180 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          stdlog.New(httpServerLogger, "", 0),
	}

	// Start the HTTPS server in a goroutine. It will block on httpsListener.Accept().
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		zlog.Info().Msg("Starting internal HTTPS server...")
		if err := httpsServer.Serve(httpsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			zlog.Error().Err(err).Msg("Internal HTTPS server error")
		}
		zlog.Info().Msg("Internal HTTPS server stopped.")
	}()

	zlog.Info().Msgf("Server is listening on %s", listenAddr)

	// Graceful shutdown handling
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		zlog.Info().Msg("Shutting down server...")

		// Stop accepting new connections
		listener.Close()

		// Gracefully shut down the HTTPS server
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := httpsServer.Shutdown(ctx); err != nil {
			zlog.Error().Err(err).Msg("HTTPS server shutdown error")
		}
	}()

	// Main loop to accept and dispatch connections
	const maxConcurrentHandlers = 8192
	handlerSemaphore := make(chan struct{}, maxConcurrentHandlers)

	numAcceptors := runtime.NumCPU()
	var wgAcceptors sync.WaitGroup
	for i := 0; i < numAcceptors; i++ {
		wgAcceptors.Add(1)
		go func() {
			defer wgAcceptors.Done()
			for {
				conn, err := listener.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						zlog.Info().Msg("Accept loop gracefully shutting down.")
						return
					}
					zlog.Error().Err(err).Msg("Failed to accept connection")
					continue
				}
				zlog.Debug().Str("client_addr", conn.RemoteAddr().String()).Msg("Accepted connection")
				select {
				case handlerSemaphore <- struct{}{}:
					go func(c net.Conn) {
						defer func() { <-handlerSemaphore }()
						handleConnection(c, httpsListener.connCh, tlsConfig)
					}(conn)
				default:
					zlog.Warn().Str("client_addr", conn.RemoteAddr().String()).Msg("Server overloaded, dropping incoming connection.")
					conn.Close()
				}
			}
		}()
	}

	// Wait for the conn Acceptors to finish shutting down
	wgAcceptors.Wait()

	// Wait for the HTTPS server to finish shutting down
	wg.Wait()
	zlog.Info().Msg("Server shut down gracefully.")
}

func handleConnection(conn net.Conn, httpsConnCh chan<- net.Conn, tlsConfig *tls.Config) {
	clientAddr := conn.RemoteAddr().String()
	br := bufio.NewReader(conn)
	peekedBytes, err := br.Peek(1)
	if err != nil {
		if err != io.EOF && !errors.Is(err, net.ErrClosed) {
			zlog.Warn().Err(err).Str("client_addr", clientAddr).Msg("Failed to peek connection")
		}
		conn.Close()
		return
	}

	if peekedBytes[0] == 0x16 { // TLS Handshake (ClientHello)
		zlog.Debug().Str("client_addr", clientAddr).Msg("First byte is 0x16, treating as HTTPS")
		// Wrap the connection to include the peeked byte for the TLS handshake
		prefixedConn := &bufConn{Conn: conn, r: br}
		tlsConn := tls.Server(prefixedConn, tlsConfig)

		// Pass the TLS connection to the central HTTPS server
		select {
		case httpsConnCh <- tlsConn:
			zlog.Debug().Str("client_addr", clientAddr).Msg("Passed TLS connection to central server.")
		default:
			// server overloaded
			zlog.Warn().Str("client_addr", clientAddr).Msg("Server overloaded, dropping incoming connection.")
			tlsConn.Close()
			return
		}
		// The http.Server now owns the connection. This goroutine is done.
		return
	}
	zlog.Debug().Str("client_addr", clientAddr).Msgf("First byte is 0x%x, treating as plain HTTP", peekedBytes[0])
	handleHttpRequest(br, conn)
	zlog.Debug().Str("client_addr", clientAddr).Msg("handleConnection goroutine for HTTP is exiting.")
}

func handleHttpRequest(br *bufio.Reader, conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		zlog.Warn().Err(err).Str("client_addr", clientAddr).Msg("Failed to set read deadline")
		return
	}

	req, err := http.ReadRequest(br)
	conn.SetReadDeadline(time.Time{}) // remove timeout
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			zlog.Warn().Str("client_addr", clientAddr).Msg("Read request timeout")
		} else if err != io.EOF {
			zlog.Warn().Err(err).Str("client_addr", clientAddr).Msg("Failed to read http request")
		}
		return
	}

	host := req.Host
	if host == "" {
		zlog.Warn().Str("client_addr", clientAddr).Msg("HTTP request is missing Host header, could not redirect.")
		_, _ = conn.Write([]byte("HTTP/1.0 400 Bad Request\r\nConnection: close\r\nContent-Length: 32\r\n\r\nBad Request: Missing Host header"))
		return
	}

	redirectURL := fmt.Sprintf("https://%s%s", host, req.URL.RequestURI())
	response := fmt.Sprintf("HTTP/1.0 301 Moved Permanently\r\nLocation: %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", redirectURL)

	zlog.Debug().Str("client_addr", clientAddr).Str("host", host).Str("redirect_url", redirectURL).Msg("Plain HTTP request. Redirecting.")

	_, err = conn.Write([]byte(response))
	if err != nil {
		zlog.Warn().Err(err).Str("client_addr", clientAddr).Msg("Failed to write redirect response")
	}
}
