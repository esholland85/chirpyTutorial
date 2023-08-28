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
	"sort"
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
	apiCfg.polkaKey = os.Getenv("POLKA_SECRET")

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
	apiR.Post("/chirps", func(w http.ResponseWriter, r *http.Request) { myDB.PostHandler(w, r, apiCfg) })
	apiR.Get("/chirps", myDB.GetChirps)
	apiR.Get("/chirps/*", myDB.GetChirp)
	apiR.Delete("/chirps/*", func(w http.ResponseWriter, r *http.Request) { myDB.DeleteHandler(w, r, apiCfg) })
	apiR.Post("/login", func(w http.ResponseWriter, r *http.Request) { LoginHandler(w, r, apiCfg, myDB) })
	apiR.Post("/polka/webhooks", func(w http.ResponseWriter, r *http.Request) { myDB.UpgradeUser(w, r, apiCfg) })
	apiR.Post("/refresh", func(w http.ResponseWriter, r *http.Request) { myDB.RefreshToken(w, r, apiCfg) })
	apiR.Post("/revoke", func(w http.ResponseWriter, r *http.Request) { myDB.RevokeToken(w, r, apiCfg) })
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
	polkaKey       string
}

type dbStructure struct {
	Chirps map[int]Chirp   `json:"chirps"`
	Users  map[int]User    `json:"users"`
	Auths  map[string]Auth `json:"auths"`
}

type Chirp struct {
	Body      string `json:"body"`
	ID        int    `json:"id"`
	Author_ID int    `json:"author_id"`
}

type User struct {
	Email         string `json:"email"`
	ID            int    `json:"id"`
	Password      string `json:"password"`
	Is_Chirpy_Red bool   `json:"is_chirpy_red"`
}

type Auth struct {
	Token       string    `json:"token"`
	Revoked     bool      `json:"revoked"`
	TimeRevoked time.Time `json:"timerevoked"`
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

func (db *DB) PostHandler(w http.ResponseWriter, r *http.Request, cfg *apiConfig) {
	userID, ok := db.AuthenticateUser(w, r, cfg)
	if !ok {
		return
	}

	wholeDB, err1 := db.LoadDB()
	if err1 != nil {
		respondWithError(w, http.StatusInternalServerError, "Server experienced an error")
		return
	}
	chirpCount := len(wholeDB.Chirps)

	type incChirp struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := incChirp{}
	err2 := decoder.Decode(&params)
	if err2 != nil {
		fmt.Println(err2)
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
		Body:      washYourMouth(params.Body),
		ID:        chirpCount + 1,
		Author_ID: userID,
	}
	db.NewDBEntry(chirpToSave, wholeDB)

	respondWithJSON(w, 201, chirpToSave)
}

func (db *DB) DeleteHandler(w http.ResponseWriter, r *http.Request, cfg *apiConfig) {
	userID, ok := db.AuthenticateUser(w, r, cfg)
	if !ok {
		return
	}

	wholeDB, err := db.LoadDB()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	chirpIDStr := r.URL.Path[len("/api/chirps/"):]
	chirpID, err1 := strconv.Atoi(chirpIDStr)
	if err1 != nil {
		respondWithError(w, http.StatusInternalServerError, "Not a valid chirp ID")
		return
	}

	oldChirps := wholeDB.Chirps

	targetChirp := oldChirps[chirpID]

	if targetChirp.Author_ID != userID {
		respondWithError(w, 403, "Only the author may delete a chirp")
		return
	}

	deletedChirp := Chirp{
		Author_ID: userID,
		ID:        chirpID,
		Body:      "Deleted",
	}

	oldChirps[chirpID] = deletedChirp

	respondWithJSON(w, 200, "Chirp Deleted")
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
		Email:         params.Email,
		ID:            userCount + 1,
		Password:      string(hashedPassword),
		Is_Chirpy_Red: false,
	}

	type response struct {
		Email         string `json:"email"`
		ID            int    `json:"id"`
		Is_Chirpy_Red bool   `json:"is_chirpy_red"`
	}

	newResponse := response{
		Email:         userToSave.Email,
		ID:            userToSave.ID,
		Is_Chirpy_Red: userToSave.Is_Chirpy_Red,
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
		Password string `json:"password"`
		Email    string `json:"email"`
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
		ID            int    `json:"id"`
		Email         string `json:"email"`
		Token         string `json:"token"`
		Refresh_Token string `json:"refresh_token"`
		Is_Chirpy_Red bool   `json:"is_chirpy_red"`
	}

	expiry := jwt.NewNumericDate(time.Now().Add(time.Hour))
	refreshExpiry := jwt.NewNumericDate(time.Now().Add(time.Hour * 1440))

	accessClaim := jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: expiry,
		Subject:   strconv.Itoa(currentUser.ID),
	}
	refreshClaim := jwt.RegisteredClaims{
		Issuer:    "chirpy-refresh",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: refreshExpiry,
		Subject:   strconv.Itoa(currentUser.ID),
	}

	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaim)
	signedAccessToken, err3 := newAccessToken.SignedString([]byte(cfg.secret))
	if err3 != nil {
		fmt.Println(err3)
		respondWithError(w, 500, "token signing failed")
		return
	}
	newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaim)
	signedRefreshToken, err4 := newRefreshToken.SignedString([]byte(cfg.secret))
	if err4 != nil {
		fmt.Println(err4)
		respondWithError(w, 500, "token signing failed")
		return
	}

	dbToken := Auth{
		Token:   signedRefreshToken,
		Revoked: false,
	}

	wholeDB.Auths[signedRefreshToken] = dbToken
	db.SaveDB(wholeDB)

	userResponse := response{
		ID:            currentUser.ID,
		Email:         currentUser.Email,
		Token:         signedAccessToken,
		Refresh_Token: signedRefreshToken,
		Is_Chirpy_Red: currentUser.Is_Chirpy_Red,
	}

	respondWithJSON(w, 200, userResponse)
}

func (db *DB) GetChirps(w http.ResponseWriter, r *http.Request) {
	authID := r.URL.Query().Get("author_id")
	sortOrder := r.URL.Query().Get("sort")

	wholeDB, err := db.LoadDB()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Server encountered an error")
		return
	}

	sortedKeys := make([]int, 0, len(wholeDB.Chirps))
	for key := range wholeDB.Chirps {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Ints(sortedKeys)

	payload := []Chirp{}

	if authID != "" {
		intID, err := strconv.Atoi(authID)
		if err != nil {
			respondWithError(w, 400, "Not a valid author ID")
			return
		}
		for _, currentKey := range sortedKeys {
			currentChirp := wholeDB.Chirps[currentKey]
			if currentChirp.Author_ID == intID {
				payload = append(payload, currentChirp)
			}
		}
	} else {
		for _, currentKey := range sortedKeys {
			currentChirp := wholeDB.Chirps[currentKey]
			payload = append(payload, currentChirp)
		}
	}

	if sortOrder != "desc" {
		respondWithJSON(w, 200, payload)
		return
	}

	reversePayload := []Chirp{}

	for i := len(payload) - 1; i >= 0; i-- {
		reversePayload = append(reversePayload, payload[i])
	}

	respondWithJSON(w, 200, reversePayload)
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

func HeaderToToken(r *http.Request, cfg *apiConfig) (*jwt.Token, error) {
	tokenHeader := r.Header.Get("Authorization")
	tokenString := strings.Replace(tokenHeader, "Bearer ", "", 1)

	type MyCustomClaims struct {
		jwt.RegisteredClaims
	}

	localFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.secret), nil
	}

	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, localFunc)
	if err != nil {
		fmt.Println(err)
		errIntro := err.Error()[:18]
		if errIntro == "token is malformed" {
			return &jwt.Token{}, errors.New("Unauthorized")
		}
		if !token.Valid {
			return &jwt.Token{}, errors.New("Unauthorized")
		} else {
			return &jwt.Token{}, err
		}
	}
	return token, nil
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
				Auths:  map[string]Auth{},
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

func (db *DB) AuthenticateUser(w http.ResponseWriter, r *http.Request, cfg *apiConfig) (int, bool) {

	token, err1 := HeaderToToken(r, cfg)
	if err1 != nil {
		fmt.Println(err1)
		errIntro := err1.Error()
		if errIntro == "Unauthorized" {
			respondWithError(w, 401, "Unauthorized")
			return 0, false
		}
		respondWithError(w, 500, "Internal Server Error")
		return 0, false
	}

	issuer, err2 := token.Claims.GetIssuer()
	if err2 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return 0, false
	}
	if issuer == "chirpy-refresh" {
		respondWithError(w, 401, "Unauthorized")
		return 0, false
	}

	userID, err3 := token.Claims.GetSubject()
	if err3 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return 0, false
	}

	intID, err4 := strconv.Atoi(userID)
	if err4 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return 0, false
	}

	return intID, true
}

func (db *DB) UpdateUser(w http.ResponseWriter, r *http.Request, cfg *apiConfig) {
	currentID, ok := db.AuthenticateUser(w, r, cfg)
	if ok {
		type UpdateAccount struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}

		decoder := json.NewDecoder(r.Body)
		params := UpdateAccount{}
		err := decoder.Decode(&params)
		if err != nil {
			respondWithError(w, 500, "Can't decode request")
			return
		}

		wholeDB, err := db.LoadDB()
		if err != nil {
			fmt.Println("failed to load database")
		}
		allUsers := wholeDB.Users

		//error handling if we somehow made it this far and the user isn't in the db?

		currentUser := User{
			Email:    params.Email,
			Password: params.Password,
			ID:       currentID,
		}

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
			Email         string `json:"email"`
			ID            int    `json:"id"`
			Is_Chirpy_Red bool   `json:"is_chirpy_red"`
		}

		myResponse := response{
			Email:         currentUser.Email,
			ID:            currentUser.ID,
			Is_Chirpy_Red: currentUser.Is_Chirpy_Red,
		}
		respondWithJSON(w, 200, myResponse)
		return
	}
}

func (db *DB) UpgradeUser(w http.ResponseWriter, r *http.Request, cfg *apiConfig) {
	keyHeader := r.Header.Get("Authorization")
	keyString := strings.Replace(keyHeader, "ApiKey ", "", 1)

	if keyString != cfg.polkaKey {
		respondWithError(w, 401, "API Key mismatch")
		return
	}

	type userData struct {
		User_ID int `json:"user_id"`
	}
	type UpgradeAccount struct {
		Event string   `json:"event"`
		Data  userData `json:"data"`
	}

	decoder := json.NewDecoder(r.Body)
	params := UpgradeAccount{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, "Can't decode request")
		return
	}
	if params.Event != "user.upgraded" {
		respondWithJSON(w, 200, []byte{})
		return
	}

	wholeDB, err1 := db.LoadDB()
	if err1 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}
	currentUser, exists := wholeDB.Users[params.Data.User_ID]
	if !exists {
		respondWithError(w, 404, "User not found")
		return
	}
	currentUser.Is_Chirpy_Red = true

	wholeDB.Users[params.Data.User_ID] = currentUser
	db.SaveDB(wholeDB)

	respondWithJSON(w, 200, []byte{})

}

func (db *DB) RefreshToken(w http.ResponseWriter, r *http.Request, cfg *apiConfig) {
	//try printing token.raw to make sure it is what I think it is.
	token, err := HeaderToToken(r, cfg)
	if err != nil {
		if err.Error() == "Unauthorized" {
			respondWithError(w, 401, "Unathorized")
			return
		}
		respondWithError(w, 500, "Internal Server Error")
		return
	}

	issuer, err2 := token.Claims.GetIssuer()
	if err2 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}
	if issuer == "chirpy-access" {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	wholeDB, err3 := db.LoadDB()
	if err3 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}
	refreshTokens := wholeDB.Auths

	for _, dbToken := range refreshTokens {
		if dbToken.Revoked && dbToken.Token == token.Raw {
			respondWithError(w, 401, "Unauthorized")
			return
		}
	}

	type ResponseObject struct {
		Token string `json:"token"`
	}

	expiry := jwt.NewNumericDate(time.Now().Add(time.Hour))

	id, err4 := token.Claims.GetSubject()
	if err4 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}

	accessClaim := jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: expiry,
		Subject:   id,
	}

	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaim)
	signedAccessToken, err5 := newAccessToken.SignedString([]byte(cfg.secret))
	if err5 != nil {
		fmt.Println(err5)
		respondWithError(w, 500, "token signing failed")
		return
	}

	response := ResponseObject{
		Token: signedAccessToken,
	}

	respondWithJSON(w, 200, response)
}

func (db *DB) RevokeToken(w http.ResponseWriter, r *http.Request, cfg *apiConfig) {
	token, err := HeaderToToken(r, cfg)
	if err != nil {
		if err.Error() == "Unauthorized" {
			respondWithError(w, 401, "Unathorized")
			return
		}
		respondWithError(w, 500, "Internal Server Error")
		return
	}

	issuer, err2 := token.Claims.GetIssuer()
	if err2 != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}
	if issuer == "chirpy-access" {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	revokedToken := Auth{
		Token:       token.Raw,
		Revoked:     true,
		TimeRevoked: time.Now(),
	}

	wholeDB, err3 := db.LoadDB()
	if err3 != nil {
		respondWithError(w, 500, "Internal Server Error")
	}
	wholeDB.Auths[token.Raw] = revokedToken
	db.SaveDB(wholeDB)

	respondWithJSON(w, 200, []byte{})
}
