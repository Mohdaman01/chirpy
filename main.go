package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"sync/atomic"
	"time"

	"github.com/Mohdaman01/chirpy/internal/auth"
	"github.com/Mohdaman01/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	jwtSecert      string
	polkaKey       string
}

type createUserReqData struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

type createUserResData struct {
	ID           uuid.UUID `json:"id"`
	Created_at   time.Time `json:"created_at"`
	Updated_at   time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

type userLoginReqData struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) getMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	hits := fmt.Sprintf(`
		<html>
  			<body>
    			<h1>Welcome, Chirpy Admin</h1>
    			<p>Chirpy has been visited %d times!</p>
 			</body>
		</html>`,
		cfg.fileserverHits.Load())
	w.Write([]byte(hits))
}

func (cfg *apiConfig) resetMatrics(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		w.WriteHeader(403)
		return
	}
	err := cfg.db.RemvoeUsers(r.Context())
	if err != nil {
		w.WriteHeader(500)
		return
	}
	err = cfg.db.RemvoeChirps(r.Context())
	if err != nil {
		w.WriteHeader(500)
		return
	}

	err = cfg.db.DeleteRefreshTokens(r.Context())
	if err != nil {
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	cfg.fileserverHits.Store(0)
	hits := fmt.Sprintf("Hits: %d\nMatrics Reseted", cfg.fileserverHits.Load())
	w.Write([]byte(hits))
}

func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	reqData := createUserReqData{}
	err := decoder.Decode(&reqData)
	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(500)
		return
	}
	email := reqData.Email
	pasword := reqData.Password

	hashedPassword, err := auth.HashPassword(pasword)

	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(500)
		return
	}

	newUserParms := database.CreateUserParams{
		Email:          email,
		HashedPassword: hashedPassword,
	}

	newUser, err := cfg.db.CreateUser(r.Context(), newUserParms)
	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(500)
		return
	}

	resData := createUserResData{
		ID:          newUser.ID,
		Created_at:  newUser.CreatedAt,
		Updated_at:  newUser.UpdatedAt,
		Email:       newUser.Email,
		IsChirpyRed: newUser.IsChirpyRed,
	}

	data, err := json.Marshal(resData)
	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(201)
	w.Write(data)

}

func (cfg *apiConfig) listChirps(w http.ResponseWriter, r *http.Request) {
	author_id := r.URL.Query().Get("author_id")
	sortQuery := r.URL.Query().Get("sort")

	if author_id != "" {
		author_idUUid, err := uuid.Parse(author_id)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		chirps, err := cfg.db.GetChirpsByUserID(r.Context(), uuid.NullUUID{UUID: author_idUUid, Valid: true})
		if err != nil {
			fmt.Printf("Error: %v", err)
			w.WriteHeader(500)
			return
		}
		chripsResSlice := make([]chripSuccessResponseBody, len(chirps))

		for index, chirp := range chirps {
			chripsResSlice[index] = chripSuccessResponseBody{
				ID:         chirp.ID.String(),
				Created_at: chirp.CreatedAt.String(),
				Updated_at: chirp.UpdatedAt.String(),
				Body:       chirp.Body,
				UserID:     chirp.UserID.UUID.String(),
			}
		}

		sort.Slice(chripsResSlice, func(i, j int) bool {
			if sortQuery == "desc" {
				return chripsResSlice[i].Created_at > chripsResSlice[j].Created_at
			}
			return chripsResSlice[i].Created_at < chripsResSlice[j].Created_at
		})

		data, err := json.Marshal(chripsResSlice)
		if err != nil {
			fmt.Printf("Error: %v", err)
			w.WriteHeader(500)
			return
		}

		w.WriteHeader(200)
		w.Write(data)
		return
	}

	chirps, err := cfg.db.GetChirps(r.Context())
	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(500)
		return
	}

	chripsResSlice := make([]chripSuccessResponseBody, len(chirps))

	for index, chirp := range chirps {
		chripsResSlice[index] = chripSuccessResponseBody{
			ID:         chirp.ID.String(),
			Created_at: chirp.CreatedAt.String(),
			Updated_at: chirp.UpdatedAt.String(),
			Body:       chirp.Body,
			UserID:     chirp.UserID.UUID.String(),
		}
	}

	sort.Slice(chripsResSlice, func(i, j int) bool {
		if sortQuery == "desc" {
			return chripsResSlice[i].Created_at > chripsResSlice[j].Created_at
		}
		return chripsResSlice[i].Created_at < chripsResSlice[j].Created_at
	})

	data, err := json.Marshal(chripsResSlice)
	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) getChirpByID(w http.ResponseWriter, r *http.Request) {
	chirpID := r.PathValue("chirpID")
	if chirpID == "" {
		w.WriteHeader(400)
		return
	}
	chirpUUID, err := uuid.Parse(chirpID)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	chirp, err := cfg.db.GetChirpByID(r.Context(), chirpUUID)
	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(404)
		return
	}
	resData := chripSuccessResponseBody{
		ID:         chirp.ID.String(),
		Created_at: chirp.CreatedAt.String(),
		Updated_at: chirp.UpdatedAt.String(),
		Body:       chirp.Body,
		UserID:     chirp.UserID.UUID.String(),
	}
	data, err := json.Marshal(resData)
	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) userLogin(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	userLoginData := userLoginReqData{}
	err := decoder.Decode(&userLoginData)
	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(500)
		return
	}

	user, err := cfg.db.GetUserByEmail(r.Context(), userLoginData.Email)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(401)
		return
	}

	isPassword, err := auth.CheckPasswordHash(userLoginData.Password, user.HashedPassword)
	if err != nil || isPassword == false {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(401)
		return
	}

	// ExpiresInSeconds is provided in seconds; convert to time.Duration correctly
	token, err := auth.MakeJWT(user.ID, cfg.jwtSecert, time.Duration(3600)*time.Second)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(500)
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(500)
		return
	}

	_, err = cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:  refreshToken,
		UserID: uuid.NullUUID{UUID: user.ID, Valid: true},
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(500)
		return
	}

	loginUserResData := createUserResData{
		ID:           user.ID,
		Created_at:   user.CreatedAt,
		Updated_at:   user.UpdatedAt,
		Email:        user.Email,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  user.IsChirpyRed,
	}

	resData, err := json.Marshal(loginUserResData)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Write(resData)

}

func (cfg *apiConfig) refreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(401)
		return
	}

	dbRefreshToken, err := cfg.db.GetRefreshToken(r.Context(), refreshToken)
	if err != nil || dbRefreshToken.ExpiresAt.Before(time.Now()) || dbRefreshToken.RevokedAt.Valid {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(401)
		return
	}

	fmt.Print(dbRefreshToken.ExpiresAt.Before(time.Now()))

	newToken, err := auth.MakeJWT(dbRefreshToken.UserID.UUID, cfg.jwtSecert, time.Duration(3600)*time.Second)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(500)
		return
	}
	resData := map[string]string{
		"token": newToken,
	}
	data, err := json.Marshal(resData)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) revokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(401)
		return
	}

	err = cfg.db.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(204)
}

func (cfg *apiConfig) updateUser(w http.ResponseWriter, r *http.Request) {
	accessToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(401)
		return
	}
	decoder := json.NewDecoder(r.Body)
	type reqData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	reqBody := reqData{}
	err = decoder.Decode(&reqBody)
	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(500)
		return
	}

	userID, err := auth.ValidateJWT(accessToken, cfg.jwtSecert)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(401)
		return
	}

	hashedPassword, err := auth.HashPassword(reqBody.Password)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(500)
		return
	}

	updaedUser, err := cfg.db.UpdateUSer(r.Context(), database.UpdateUSerParams{
		Email:          reqBody.Email,
		HashedPassword: hashedPassword,
		ID:             userID,
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(500)
		return
	}

	type resData struct {
		ID          uuid.UUID `json:"id"`
		Created_at  time.Time `json:"created_at"`
		Updated_at  time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		ISChirpyRed bool      `json:"is_chirpy_red"`
	}

	resBody := resData{
		ID:          updaedUser.ID,
		Created_at:  updaedUser.CreatedAt,
		Updated_at:  updaedUser.UpdatedAt,
		Email:       updaedUser.Email,
		ISChirpyRed: updaedUser.IsChirpyRed,
	}

	data, err := json.Marshal(resBody)
	if err != nil {
		fmt.Printf("Error: %v", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Write(data)

}

func (cfg *apiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {
	accessToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(401)
		return
	}

	userID, err := auth.ValidateJWT(accessToken, cfg.jwtSecert)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(401)
		return
	}

	chirpIDStr := r.PathValue("chirpID")
	if chirpIDStr == "" {
		w.WriteHeader(400)
		return
	}
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	chirp, err := cfg.db.GetChirpByIDandUserID(r.Context(), database.GetChirpByIDandUserIDParams{
		ID:     chirpID,
		UserID: uuid.NullUUID{UUID: userID, Valid: true},
	})
	if err != nil || chirp.ID == uuid.Nil {
		fmt.Printf("Error: %v\nID: %s", err, chirpIDStr)
		w.WriteHeader(403)
		return
	}

	err = cfg.db.DeleteChirpByID(r.Context(), database.DeleteChirpByIDParams{
		ID:     chirpID,
		UserID: uuid.NullUUID{UUID: userID, Valid: true},
	})
	if err != nil {
		fmt.Printf("Error: %v\nID: %s", err, chirpIDStr)
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(204)
}

func (cfg *apiConfig) polkaWebhooks(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)

	apiKey, err := auth.GetAPIKey(r.Header)

	if err != nil || apiKey != cfg.polkaKey {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(401)
		return
	}

	type polkaWebhookData struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}

	webhookData := polkaWebhookData{}

	err = decoder.Decode(&webhookData)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(500)
		return
	}

	if webhookData.Event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}
	userUUID, err := uuid.Parse(webhookData.Data.UserID)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(500)
		return
	}

	user, err := cfg.db.GetUserByID(r.Context(), userUUID)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(404)
		return
	}
	fmt.Printf("Upgrading user %s to Chirpy Red\n", user.Email)
	_, err = cfg.db.UpdateUserToChipryRedByID(r.Context(), userUUID)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(204)
	w.Write([]byte{})
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	jwtSecert := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("%v", err)
	}

	dqQueries := database.New(db)

	fileServer := http.FileServer(http.Dir("."))

	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
		db:             dqQueries,
		platform:       platform,
		jwtSecert:      jwtSecert,
		polkaKey:       polkaKey,
	}

	serveMux := http.NewServeMux()
	serveMux.Handle("/app/", http.StripPrefix("/app/", apiCfg.middlewareMetricsInc(fileServer)))
	serveMux.Handle("GET /api/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	serveMux.HandleFunc("GET /admin/metrics", apiCfg.getMetrics)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetMatrics)
	serveMux.HandleFunc("POST /api/chirps", apiCfg.validate_chirp)
	serveMux.HandleFunc("POST /api/users", apiCfg.createUser)
	serveMux.HandleFunc("GET /api/chirps", apiCfg.listChirps)
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpByID)
	serveMux.HandleFunc("POST /api/login", apiCfg.userLogin)
	serveMux.HandleFunc("POST /api/refresh", apiCfg.refreshToken)
	serveMux.HandleFunc("POST /api/revoke", apiCfg.revokeRefreshToken)
	serveMux.HandleFunc("PUT /api/users", apiCfg.updateUser)
	serveMux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirp)
	serveMux.HandleFunc("POST /api/polka/webhooks", apiCfg.polkaWebhooks)

	server := http.Server{
		Handler: serveMux,
		Addr:    ":8080",
	}

	log.Printf("Serving %s on %s\n", ".", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
