package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

func main() {
	//r := http.NewServeMux()
	r := chi.NewRouter()
	apiR := chi.NewRouter()
	adminR := chi.NewRouter()
	corsWrapped := middlewareCors(r)
	httpServer := http.Server{
		Addr:    "localhost:8080",
		Handler: corsWrapped,
	}
	apiCfg := &apiConfig{}

	directory := http.Dir(".")
	fsHandler := http.StripPrefix("/app", apiCfg.middlewareMetricsInc(http.FileServer(directory)))

	r.Mount("/api", apiR)
	r.Mount("/admin", adminR)

	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)
	apiR.Get("/healthz", healthz)
	//apiR.Post("/validate_chirp", validationHandler)
	apiR.Post("/chirps", validationHandler)
	adminR.Get("/metrics", func(w http.ResponseWriter, r *http.Request) { hitzHandler(w, r, apiCfg) })

	httpServer.ListenAndServe()
}

type responseRecorder struct {
	http.ResponseWriter
	Status int
}

type apiConfig struct {
	fileserverHits int
}

func healthz(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func hitzHandler(w http.ResponseWriter, req *http.Request, cfg *apiConfig) {
	tmpl, err := template.ParseFiles("hitzTemplate.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Hits int
	}{
		Hits: cfg.fileserverHits,
	}

	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		recorder := &responseRecorder{ResponseWriter: w, Status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		if recorder.Status >= 200 && recorder.Status < 400 {
			fmt.Println("New hit!")
			cfg.fileserverHits += 1
			return
		}
		fmt.Println(recorder.Status)
	})
}

func (r *responseRecorder) WriteHeader(status int) {
	r.Status = status
	r.ResponseWriter.WriteHeader(status)
}

func validationHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	type chirpValid struct {
		Cleaned_body string `json:"cleaned_body"`
	}

	if len(params.Body) == 0 {
		respondWithError(w, 400, "No body detected")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}

	respBody := chirpValid{
		Cleaned_body: washYourMouth(params.Body),
	}

	respondWithJSON(w, 200, respBody)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type chirpError struct {
		Error string `json:"error"`
	}

	errorResponse := chirpError{
		Error: msg,
	}

	dat, err := json.Marshal(errorResponse)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func washYourMouth(body string) string {
	broken := strings.Split(body, " ")
	filter := []string{"kerfuffle", "sharbert", "fornax"}

	for i, s := range broken {
		for _, f := range filter {
			if strings.ToLower(s) == f {
				broken[i] = "****"
				break
			}
		}
	}

	putTogether := strings.Join(broken, " ")
	return putTogether
}
