package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	if os.Getenv("AUTHZ_CSRF_SECRET") == "" {
		log.Print("warning: AUTHZ_CSRF_SECRET is unset; generated CSRF tokens will be invalidated by a restart")
	}

	database, err := openStore(cfg.DBPath)
	if err != nil {
		log.Fatalf("database initialization failed: %v", err)
	}
	defer database.Close()

	startupContext, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	if err := database.seed(startupContext, cfg.AdminEmails, cfg.InitialViewers, time.Now().UTC()); err != nil {
		cancelStartup()
		log.Fatalf("permission initialization failed: %v", err)
	}
	if err := database.cleanupEvents(startupContext, time.Now().UTC(), cfg.RetentionDays); err != nil {
		cancelStartup()
		log.Fatalf("event retention cleanup failed: %v", err)
	}
	cancelStartup()

	serviceContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go runDailyMaintenance(serviceContext, database, cfg)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           newApp(cfg, database).handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("authorization service listening on %s", cfg.ListenAddr)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-serviceContext.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("authorization server failed: %v", err)
		}
	}
}

func runDailyMaintenance(ctx context.Context, database *store, cfg config) {
	run := func() {
		maintenanceContext, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		now := time.Now().UTC()
		if err := database.cleanupEvents(maintenanceContext, now, cfg.RetentionDays); err != nil {
			log.Printf("event retention cleanup failed: %v", err)
		}
		filename, err := database.backup(maintenanceContext, cfg.BackupDir, now, cfg.BackupRetentionDays)
		if err != nil {
			log.Printf("database backup failed: %v", err)
			return
		}
		log.Printf("database backup completed: %s", filename)
	}

	run()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
