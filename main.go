package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/goozt/gopgbase/infra/ca/internal/ca"
	"github.com/goozt/gopgbase/infra/ca/internal/db"
	"github.com/goozt/gopgbase/infra/ca/internal/utils"
)

type ArgOptions struct {
	Port    *string
	Help    *bool
	Gen     *bool
	Force   *bool
	Client  *bool
	RootCA  *string
	TLSCert *string
	TLSKey  *string
}

func init() {
	caDB := db.InitDB()
	if caDB == nil {
		slog.Error("failed to initialize database")
		os.Exit(1)
	}
}

func parseArgs() ArgOptions {
	var opts ArgOptions

	helperText := `Usage: ca-server [options] [certs_directory]

Options:
  -p string
	API Listener Port (default "8000")
  -h, --help
	Show this help message
  -g, --gen
	Generate CA certificate in the specified directory (default: current working directory)
  -f, --force
	Force CA generation even if it already exists (use with -g)
  -c, --client
	Generate root client certificate signed by the CA (default: false, use with -g)
  --tls-cert string
	Path to TLS certificate file (enables HTTPS when set together with --tls-key)
  --tls-key string
	Path to TLS private key file (enables HTTPS when set together with --tls-cert)

Arguments:
  certs_directory
	Optional path to the directory containing the CA certificate (ca.crt).
	Alternatively, you can set the CERTS_DIR environment variable.
	If both are provided, the command-line argument takes precedence.`
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, helperText)
	}
	opts.Port = flag.String("p", "8000", "API Listener Port")
	opts.Help = flag.Bool("h", false, "show help")
	opts.Gen = flag.Bool("gen", false, "generate CA")
	opts.Force = flag.Bool("force", false, "force CA generation even if it already exists")
	opts.Client = flag.Bool("client", false, "generate root client certificate signed by the CA")
	opts.RootCA = flag.String("root", ".rootCA", "root CA certificate directory (default: .rootCA)")
	opts.TLSCert = flag.String("tls-cert", "", "TLS certificate file path (enables HTTPS)")
	opts.TLSKey = flag.String("tls-key", "", "TLS private key file path (enables HTTPS)")
	flag.BoolVar(opts.Gen, "g", false, "generate CA")
	flag.BoolVar(opts.Force, "f", false, "force CA generation even if it already exists")
	flag.BoolVar(opts.Client, "c", false, "generate root client certificate signed by the CA")
	flag.StringVar(opts.RootCA, "r", ".rootCA", "root CA certificate directory (default: .rootCA)")
	flag.Parse()
	return opts
}

func initLogger() {
	logLevel := slog.LevelInfo
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))
}

func generateCerts(opts ArgOptions, certDir string) {
	if *opts.Gen {
		if !ca.CheckRootCAExists(*opts.RootCA) || *opts.Force {
			GenerateCA(*opts.RootCA)
		}
		if !ca.CheckCAExists(certDir) || *opts.Force {
			GenerateInterCA(certDir)
		}
	}
	if *opts.Client && (!ca.CheckClientRootCertExists(certDir) || *opts.Force) {
		GenerateClientRootCert(certDir, certDir+"/ca.crt", certDir+"/ca.key")
	}
}

func listenAndServe(server *http.Server, tlsCert, tlsKey string) {
	if tlsCert != "" && tlsKey != "" {
		slog.Info("starting API server (HTTPS)", "addr", server.Addr)
		if err := server.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed to start", "error", err)
			os.Exit(1)
		}
		return
	}
	slog.Info("starting API server (HTTP)", "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server failed to start", "error", err)
		os.Exit(1)
	}
}

func main() {
	opts := parseArgs()
	if *opts.Help {
		flag.Usage()
		return
	}

	var certsDirPath string
	if flag.NArg() > 0 {
		certsDirPath = flag.Arg(0)
	}

	initLogger()

	certDir := utils.GetCertDir(certsDirPath)
	generateCerts(opts, certDir)
	utils.VerifyCertDir(*opts.RootCA, certDir)

	mux := http.NewServeMux()
	registerRoutes(mux)

	handler := recoveryMiddleware(
		loggingMiddleware(
			securityHeadersMiddleware(
				rateLimitMiddleware(
					errorHandlingMiddleware(mux),
				),
			),
		),
	)

	server := &http.Server{
		Addr:           ":" + *opts.Port,
		Handler:        handler,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	go listenAndServe(server, *opts.TLSCert, *opts.TLSKey)
	gracefulShutdown(server)
}

func gracefulShutdown(server *http.Server) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig := <-quit
	slog.Info("shutting down server", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped gracefully")
}
