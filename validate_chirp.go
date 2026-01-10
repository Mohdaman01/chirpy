package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/Mohdaman01/chirpy/internal/auth"
	"github.com/Mohdaman01/chirpy/internal/database"
	"github.com/google/uuid"
)

type chirpRequestBody struct {
	Body string `json:"body"`
}

type chirpErrorResponseBody struct {
	Error string `json:"error"`
}

type chripSuccessResponseBody struct {
	ID         string `json:"id"`
	Created_at string `json:"created_at"`
	Updated_at string `json:"updated_at"`
	Body       string `json:"body"`
	UserID     string `json:"user_id"`
}

func (cfg *apiConfig) validate_chirp(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Println("Error getting bearer token:", err)
		w.WriteHeader(401)
		return
	}

	userId, err := auth.ValidateJWT(token, cfg.jwtSecert)
	if err != nil {
		log.Println("Error validating JWT:", err)
		w.WriteHeader(401)
		return
	}

	decoder := json.NewDecoder(r.Body)
	data := chirpRequestBody{}
	err = decoder.Decode(&data)

	if err != nil {
		chripErr := chirpErrorResponseBody{
			Error: "Something went wrong",
		}
		errData, err := json.Marshal(chripErr)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(500)
		w.Write(errData)
		return
	}

	if len(data.Body) > 140 {
		chripErr := chirpErrorResponseBody{
			Error: "Chirp is too long",
		}
		errData, err := json.Marshal(chripErr)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(400)
		w.Write(errData)
		return
	}

	chirpSlice := strings.Split(data.Body, " ")

	for index, word := range chirpSlice {
		tempWord := strings.ToLower(word)
		if tempWord == "kerfuffle" || tempWord == "sharbert" || tempWord == "fornax" {
			chirpSlice[index] = "****"
		}
	}
	chirp := strings.Join(chirpSlice, " ")
	user_id := userId.String()

	parsedUUID, err := uuid.Parse(user_id)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	createChripParams := database.CreateChirpParams{
		Body:   chirp,
		UserID: uuid.NullUUID{UUID: parsedUUID, Valid: true},
	}

	chripData, err := cfg.db.CreateChirp(r.Context(), createChripParams)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	tempResParams := chripSuccessResponseBody{
		ID:         chripData.ID.String(),
		Created_at: chripData.CreatedAt.String(),
		Updated_at: chripData.UpdatedAt.String(),
		Body:       chripData.Body,
		UserID:     chripData.UserID.UUID.String(),
	}

	chripResData, err := json.Marshal(tempResParams)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(201)
	w.Write(chripResData)
}
