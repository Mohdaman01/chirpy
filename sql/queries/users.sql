-- name: CreateUser :one
INSERT INTO users (id,created_at,updated_at,email,hashed_password) 
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: RemvoeUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email=$1 LIMIT 1;

-- name: UpdateUSer :one
UPDATE users
SET updated_at = NOW(),email = $1,hashed_password = $2
WHERE id = $3
RETURNING *;

-- name: UpdateUserToChipryRedByID :one
UPDATE users
SET updated_at = NOW(), is_chirpy_red = TRUE
WHERE id = $1
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;