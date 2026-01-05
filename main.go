package main

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfd *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfd.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfd *apiConfig) getMetrics() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		hits := fmt.Sprintf("Hits: %d", cfd.fileserverHits.Load())
		w.Write([]byte(hits))
	})
}

func (cfd *apiConfig) resetMatrics() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		cfd.fileserverHits.Store(0)
		hits := fmt.Sprintf("Hits: %d\nMatrics Reseted", cfd.fileserverHits.Load())
		w.Write([]byte(hits))
	})
}

func main() {
	fileServer := http.FileServer(http.Dir("."))

	apiCfg := &apiConfig{}

	serveMux := http.NewServeMux()
	serveMux.Handle("/app/", http.StripPrefix("/app/", apiCfg.middlewareMetricsInc(fileServer)))
	serveMux.Handle("GET /api/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	serveMux.Handle("GET /api/metrics", apiCfg.getMetrics())
	serveMux.Handle("POST /api/reset", apiCfg.resetMatrics())

	server := http.Server{
		Handler: serveMux,
		Addr:    ":8080",
	}

	log.Printf("Serving %s on %s\n", ".", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
