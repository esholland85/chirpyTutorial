package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// missing logic in the login handler
func main() {
	r := chi.NewRouter()
	apiR := chi.NewRouter()
	adminR := chi.NewRouter()
	corsWrapped := middlewareCors(r)
	httpServer := http.Server{
		Addr:    "localhost:8080",
		Handler: corsWrapped,
	}
	godotenv.Load()
	apiCfg := &apiConfig{}
	apiCfg.secret = os.Getenv("JWT_SECRET")

	directory := http.Dir(".")
	fsHandler := http.StripPrefix("/app", apiCfg.middlewareMetricsInc(http.FileServer(directory)))

	myDB := DB{
		path: "database.json",
		mux:  &sync.RWMutex{},
	}
	//for frequent repeated tests, I make sure there IS a database, remove it, and make it again.
	//var dbg bool
	//flag.BoolVar(&dbg, "debug", false, "Enable debug mode")

	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	if *dbg {
		myDB.LoadDB()
		os.Remove("database.json")
		myDB.LoadDB()
	}

	r.Mount("/api", apiR)
	r.Mount("/admin", adminR)

	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)
	apiR.Get("/healthz", healthz)
	apiR.Post("/chirps", myDB.ValidationHandler)
	apiR.Get("/chirps", myDB.GetChirps)
	apiR.Get("/chirps/*", myDB.GetChirp)
	apiR.Post("/login", func(w http.ResponseWriter, r *http.Request) { LoginHandler(w, r, apiCfg, myDB) })
	apiR.Post("/users", myDB.UserHandler)
	apiR.Put("/users", func(w http.ResponseWriter, r *http.Request) { myDB.UpdateUser(w, r, apiCfg) })
	adminR.Get("/metrics", func(w http.ResponseWriter, r *http.Request) { hitzHandler(w, r, apiCfg) })

	httpServer.ListenAndServe()
}

type DB struct {
	path string
	mux  *sync.RWMutex
}

type responseRecorder struct {
	http.ResponseWriter
	Status int
}

type apiConfig struct {
	fileserverHits int
	secret         string
}

type dbStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

type Chirp struct {
	Body string `json:"body"`
	ID   int    `json:"id"`
}

type User struct {
	Email    string `json:"email"`
	ID       int    `json:"id"`
	Password string `json:"password"`
}

func healthz(w http.ResponseWriter, req *http.Request) {
	fmt.Println("healthz hit")
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
	fmt.Println("hitzhandler triggered")
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
	fmt.Println("responserecorder... setup?")
}

func (db *DB) ValidationHandler(w http.ResponseWriter, r *http.Request) {
	oldChirps, err1 := db.LoadDB()
	if err1 != nil {
		respondWithError(w, http.StatusInternalServerError, "Server experienced an error")
		return
	}
	chirpCount := len(oldChirps.Chirps)

	decoder := json.NewDecoder(r.Body)
	params := Chirp{}
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

	chirpToSave := Chirp{
		Body: washYourMouth(params.Body),
		ID:   chirpCount + 1,
	}
	db.NewDBEntry(chirpToSave, oldChirps)

	respondWithJSON(w, 201, chirpToSave)
}

func (db *DB) UserHandler(w http.ResponseWriter, r *http.Request) {
	oldPosts, err1 := db.LoadDB()
	if err1 != nil {
		respondWithError(w, http.StatusInternalServerError, "Server experienced an error")
		return
	}
	userCount := len(oldPosts.Users)

	decoder := json.NewDecoder(r.Body)
	params := User{}
	err2 := decoder.Decode(&params)
	if err2 != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	if len(params.Email) == 0 {
		respondWithError(w, 400, "No email detected")
		return
	}
	if len(params.Password) == 0 {
		respondWithError(w, 400, "No password detected")
		return
	}

	hashedPassword, err3 := bcrypt.GenerateFromPassword([]byte(params.Password), 0)
	if err3 != nil {
		fmt.Println("failed to hash password")
		return
	}

	userToSave := User{
		Email:    params.Email,
		ID:       userCount + 1,
		Password: string(hashedPassword),
	}

	type response struct {
		Email string `json:"email"`
		ID    int    `json:"id"`
	}

	newResponse := response{
		Email: userToSave.Email,
		ID:    userToSave.ID,
	}

	err4 := db.NewUser(userToSave)
	if err4 != nil {
		respondWithError(w, 500, err4.Error())
		return
	}

	respondWithJSON(w, 201, newResponse)
}

func LoginHandler(w http.ResponseWriter, r *http.Request, cfg *apiConfig, db DB) {
	type LoginAttempt struct {
		Password           string `json:"password"`
		Email              string `json:"email"`
		Expires_in_seconds int    `json:"expires_in_seconds"`
	}

	decoder := json.NewDecoder(r.Body)
	params := LoginAttempt{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, "Can't decode request")
		return
	}

	if len(params.Email) == 0 {
		respondWithError(w, 400, "No email detected")
		return
	}
	if len(params.Password) == 0 {
		respondWithError(w, 400, "No password detected")
		return
	}

	wholeDB, err := db.LoadDB()
	if err != nil {
		fmt.Println(err)
		return
	}

	allUsers := wholeDB.Users

	var currentUser User
	currentUser.ID = 0

	for _, user := range allUsers {
		if user.Email == params.Email {
			currentUser = user
			break
		}
	}

	if currentUser.ID == 0 {
		respondWithError(w, 404, "User email not found")
		return
	}
	err2 := bcrypt.CompareHashAndPassword([]byte(currentUser.Password), []byte(params.Password))
	if err2 != nil {
		respondWithError(w, 401, "Incorrect password")
		return
	}
	type response struct {
		ID    int    `json:"id"`
		Email string `json:"email"`
		Token string `json:"token"`
	}

	var expiry jwt.NumericDate
	if params.Expires_in_seconds == 0 || params.Expires_in_seconds > 86400 {
		expiry = *jwt.NewNumericDate(time.Now().Add(time.Hour * 24))
	} else {
		expiry = *jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(params.Expires_in_seconds)))
	}

	newClaim := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: &expiry,
		Subject:   strconv.Itoa(currentUser.ID),
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaim)
	signedToken, err3 := newToken.SignedString([]byte(cfg.secret))
	if err3 != nil {
		fmt.Println(err3)
		respondWithError(w, 500, "token signing failed")
		return
	}

	userResponse := response{
		ID:    currentUser.ID,
		Email: currentUser.Email,
		Token: signedToken,
	}

	respondWithJSON(w, 200, userResponse)
}

func (db *DB) GetChirps(w http.ResponseWriter, r *http.Request) {
	fullDB, err := db.LoadDB()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Server encountered an error")
	}
	payload := []Chirp{}
	for _, currentChirp := range fullDB.Chirps {
		payload = append(payload, currentChirp)
	}

	respondWithJSON(w, 200, payload)
}

func (db *DB) GetChirp(w http.ResponseWriter, r *http.Request) {
	chirpIDStr := r.URL.Path[len("/api/chirps/"):]
	chirpID, err := strconv.Atoi(chirpIDStr)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Not a valid chirp ID")
		return
	}

	oldChirps, err := db.LoadDB()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Server encountered an error")
	}

	payload, exists := oldChirps.Chirps[chirpID]
	if !exists {
		respondWithError(w, 404, "Chirp not found")
		return
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

func (db *DB) LoadDB() (dbStructure, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()
	contents, err := os.ReadFile(db.path)
	if err != nil {
		if os.IsNotExist(err) {

			saveFile, err2 := json.Marshal(dbStructure{
				Chirps: map[int]Chirp{},
				Users:  map[int]User{},
			})
			if err2 != nil {
				return dbStructure{}, nil
			}
			os.WriteFile(db.path, saveFile, os.ModePerm)
			return dbStructure{}, err
		}
		fmt.Println(err)
	}

	dbData := dbStructure{}

	err = json.Unmarshal([]byte(contents), &dbData)
	if err != nil {
		fmt.Println("Error:", err)
		return dbStructure{}, err
	}

	return dbData, nil
}

func (db *DB) SaveDB(currentDB dbStructure) {
	db.mux.Lock()
	defer db.mux.Unlock()
	saveFile, err := json.Marshal(currentDB)
	if err != nil {
		fmt.Println(err)
	}

	os.WriteFile(db.path, saveFile, os.ModePerm)
}

func (db *DB) NewDBEntry(newChirp Chirp, currentDB dbStructure) dbStructure {
	currentDB.Chirps[newChirp.ID] = newChirp
	db.SaveDB(currentDB)
	return currentDB
}

func (db *DB) NewUser(newUser User) error {
	//need to enforce email singularity
	currentDB, err := db.LoadDB()
	if err != nil {
		fmt.Println(err)
		return err
	}

	wholeDB, err2 := db.LoadDB()
	if err2 != nil {
		fmt.Println("failed to load database")
	}
	allUsers := wholeDB.Users
	exists := false

	for _, user := range allUsers {
		if user.Email == newUser.Email {
			exists = true
			break
		}
	}

	if exists {
		err := errors.New("User already exists")
		return err
	}
	currentDB.Users[newUser.ID] = newUser
	db.SaveDB(currentDB)
	return nil
}

func (db *DB) AuthenticateUser(w http.ResponseWriter, r *http.Request, cfg *apiConfig) (User, bool) {
	type UpdateAccount struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := UpdateAccount{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, "Can't decode request")
		return User{}, false
	}

	tokenHeader := r.Header.Get("Authorization")
	tokenString := strings.Replace(tokenHeader, "Bearer ", "", 1)

	type MyCustomClaims struct {
		jwt.RegisteredClaims
	}

	localFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.secret), nil
	}

	token, err2 := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, localFunc)
	if err2 != nil {
		fmt.Println(err2)
		errIntro := err2.Error()[:18]
		if errIntro == "token is malformed" {
			respondWithError(w, 401, "Unauthorized")
			return User{}, false
		}
		if !token.Valid {
			respondWithError(w, 401, "Unauthorized")
		}
		return User{}, false
	}

	id, err := token.Claims.GetSubject()
	if err != nil {
		respondWithError(w, 500, "Internal Server Error")
		return User{}, false
	}

	intID, err3 := strconv.Atoi(id)
	if err3 != nil {
		fmt.Println("failed conversion")
	}

	authUser := User{
		ID:       intID,
		Email:    params.Email,
		Password: params.Password,
	}

	return authUser, true
}

func (db *DB) UpdateUser(w http.ResponseWriter, r *http.Request, cfg *apiConfig) {
	currentUser, ok := db.AuthenticateUser(w, r, cfg)
	if ok {
		wholeDB, err := db.LoadDB()
		if err != nil {
			fmt.Println("failed to load database")
		}
		allUsers := wholeDB.Users

		hashedPassword, err2 := bcrypt.GenerateFromPassword([]byte(currentUser.Password), 0)
		if err2 != nil {
			fmt.Println("failed to hash password")
			return
		}

		hashedUser := User{
			ID:       currentUser.ID,
			Email:    currentUser.Email,
			Password: string(hashedPassword),
		}

		allUsers[currentUser.ID] = hashedUser
		db.SaveDB(wholeDB)
		type response struct {
			Email string `json:"email"`
			ID    int    `json:"id"`
		}

		myResponse := response{
			Email: currentUser.Email,
			ID:    currentUser.ID,
		}
		respondWithJSON(w, 200, myResponse)
		return
	}
}
