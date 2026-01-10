-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens(token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES ($1, NOW(), NOW(), $2, NOW() + INTERVAL '60 days', NULL)
RETURNING *;

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens
INNER JOIN users ON refresh_tokens.user_id = users.id
WHERE token = $1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(), updated_at = NOW()
WHERE token = $1;

-- name: DeleteRefreshTokens :exec
DELETE FROM refresh_tokens;