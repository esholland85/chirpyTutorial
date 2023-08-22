package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
)

func main() {
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

	//for frequent repeated tests, I make sure there IS a database, remove it, and make it again.
	getChirps("database.json")
	os.Remove("database.json")
	getChirps("database.json")

	r.Mount("/api", apiR)
	r.Mount("/admin", adminR)

	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)
	apiR.Get("/healthz", healthz)
	//apiR.Post("/validate_chirp", validationHandler)
	apiR.Post("/chirps", validationHandler)
	apiR.Get("/chirps", dbRequestHandler)
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

type chirpRAM struct {
	Chirps map[int]chirp `json:"chirps"`
}

type chirp struct {
	Body string `json:"body"`
	ID   int    `json:"id"`
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
	oldChirps, err1 := getChirps("database.json")
	if err1 != nil {
		respondWithError(w, http.StatusInternalServerError, "Server experienced an error")
		return
	}
	chirpCount := len(oldChirps.Chirps)

	decoder := json.NewDecoder(r.Body)
	params := chirp{}
	err2 := decoder.Decode(&params)
	if err2 != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	if len(params.Body) == 0 {
		respondWithError(w, 400, "No body detected")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}

	chirpToSave := chirp{
		Body: washYourMouth(params.Body),
		ID:   chirpCount + 1,
	}
	saveChirps(chirpToSave, "database.json")

	respondWithJSON(w, 201, chirpToSave)
}

func dbRequestHandler(w http.ResponseWriter, r *http.Request) {
	oldChirps, err := getChirps("database.json")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Server encountered an error")
	}
	payload := []chirp{}
	for _, currentChirp := range oldChirps.Chirps {
		payload = append(payload, currentChirp)
	}

	respondWithJSON(w, 200, payload)
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

func getChirps(path string) (chirpRAM, error) {
	//get and save should both be locking... something about a mux?
	//I've done it before, forgotten how to do it now, and need to refresh.
	contents, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {

			saveFile, err2 := json.Marshal(chirpRAM{Chirps: map[int]chirp{}})
			if err2 != nil {
				return chirpRAM{}, nil
			}
			os.WriteFile(path, saveFile, os.ModePerm)
			return chirpRAM{}, err
		}
		fmt.Println(err)
	}

	chirpsData := chirpRAM{}

	err = json.Unmarshal([]byte(contents), &chirpsData)
	if err != nil {
		fmt.Println("Error:", err)
		return chirpRAM{}, err
	}

	return chirpsData, nil
}

func saveChirps(newChirp chirp, path string) {
	oldChirps, err := getChirps(path)
	if err != nil {
		fmt.Println(err)
	}
	oldChirps.Chirps[newChirp.ID] = newChirp
	saveFile, err := json.Marshal(oldChirps)
	if err != nil {
		fmt.Println(err)
	}

	os.WriteFile(path, saveFile, os.ModePerm)
}
