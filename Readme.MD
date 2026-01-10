# Chirpy

Chirpy is a Twitter-like application built with Go. It provides a RESTful API for users to create accounts, log in, post "chirps", and manage their sessions with JWT and refresh tokens.

## Features

*   **User Management**: Register new users, log in, and manage user profiles.
*   **Chirp Management**: Create, view, and delete chirps.
*   **Authentication**: Secure authentication using JWTs and refresh tokens, with Argon2id for password hashing.
*   **Database**: PostgreSQL database integration, with `sqlc` for type-safe database interactions.
*   **Admin Features**: (Potentially) administrative functionalities, possibly related to managing users or content.
*   **Metrics**: Track file server hits.

## Technologies Used

*   **Go**: The primary programming language.
*   **PostgreSQL**: The relational database.
*   **`github.com/alexedwards/argon2id`**: For secure password hashing.
*   **`github.com/golang-jwt/jwt/v5`**: For JSON Web Token (JWT) authentication.
*   **`github.com/google/uuid`**: For generating universally unique identifiers.
*   **`github.com/joho/godotenv`**: For loading environment variables from a `.env` file.
*   **`github.com/lib/pq`**: PostgreSQL driver for Go.
*   **`sqlc`**: Generates type-safe Go code from SQL.

## Project Structure

```
.github/                 # GitHub workflows (e.g., CI/CD)
assets/                  # Static assets (CSS, JavaScript, images)
internal/
├── auth/                # Authentication-related logic (JWT, password hashing)
├── database/            # `sqlc` generated database code and database connection setup
sql/
├── queries/             # SQL queries for `sqlc` to generate Go code from
└── schema/              # Database schema migrations
go.mod                   # Go module definition
index.html               # Main HTML file
main.go                  # Main application entry point and API routes
Readme.MD                # Project documentation
sqlc.yaml                # `sqlc` configuration file
validate_chirp.go        # Chirp validation logic
```

## Setup and Installation

### Prerequisites

*   Go (version 1.25.5 or higher)
*   PostgreSQL
*   `sqlc` (for generating database code)

### Steps

1.  **Clone the repository**:

    ```bash
    git clone https://github.com/Mohdaman01/chirpy.git
    cd chirpy
    ```

2.  **Set up environment variables**:

    Create a `.env` file in the root directory of the project with the following variables:

    ```env
    JWT_SECRET=your_jwt_secret_key
    POLKA_KEY=your_polka_webhook_secret
    DB_CONN_STRING="host=localhost port=5432 user=youruser password=yourpassword dbname=yourdatabase sslmode=disable"
    ```

    *   `JWT_SECRET`: A strong, random key used for signing JWTs.
    *   `POLKA_KEY`: A secret key for Polka webhook verification (if applicable).
    *   `DB_CONN_STRING`: Your PostgreSQL connection string.

3.  **Install Go dependencies**:

    ```bash
    go mod download
    ```

4.  **Run database migrations**:

    (You'll need a migration tool, e.g., `golang-migrate/migrate`. Assuming you have one configured, or run the SQL files manually in order.)

    Example with `migrate` CLI:
    ```bash
    migrate -path sql/schema -database "$DB_CONN_STRING" up
    ```

5.  **Generate `sqlc` code**:

    ```bash
    sqlc generate
    ```

6.  **Run the application**:

    ```bash
    go run .
    ```

    The server will start on the port specified in your `main.go` (default usually 8080).

## API Endpoints

The following API endpoints are available:

### Health Check

*   `GET /api/healthz`
    *   **Description**: Checks the health of the API.
    *   **Response**: `200 OK` with "OK" in the body.

### Metrics and Admin

*   `GET /admin/metrics`
    *   **Description**: Displays the number of file server hits.
    *   **Response**: HTML page showing the hit count.
*   `POST /admin/reset`
    *   **Description**: Resets the file server hit counter and removes all users, chirps and refresh tokens from the database (only in `dev` platform).
    *   **Response**: `200 OK` with updated hit count and "Matrics Reseted".

### Users

*   `POST /api/users`
    *   **Description**: Registers a new user.
    *   **Request Body**:
        ```json
        {
            "email": "user@example.com",
            "password": "a_strong_password"
        }
        ```
    *   **Response**: `201 Created` with the new user's details, JWT, and refresh token.
*   `PUT /api/users`
    *   **Description**: Updates an existing user's email or password. Requires a valid JWT in the Authorization header.
    *   **Request Headers**: `Authorization: Bearer <JWT>`
    *   **Request Body**:
        ```json
        {
            "email": "new_email@example.com",
            "password": "new_strong_password"
        }
        ```
    *   **Response**: `200 OK` with the updated user's details.

### User Authentication

*   `POST /api/login`
    *   **Description**: Authenticates a user and provides JWT and refresh tokens.
    *   **Request Body**:
        ```json
        {
            "email": "user@example.com",
            "password": "a_strong_password"
        }
        ```
    *   **Response**: `200 OK` with user details, JWT, and refresh token.
*   `POST /api/refresh`
    *   **Description**: Refreshes an expired JWT using a valid refresh token.
    *   **Request Headers**: `Authorization: Bearer <Refresh Token>`
    *   **Response**: `200 OK` with a new JWT.
*   `POST /api/revoke`
    *   **Description**: Revokes a refresh token, invalidating it.
    *   **Request Headers**: `Authorization: Bearer <Refresh Token>`
    *   **Response**: `204 No Content`.

### Chirps

*   `POST /api/chirps`
    *   **Description**: Creates a new chirp. Requires a valid JWT in the Authorization header.
    *   **Request Headers**: `Authorization: Bearer <JWT>`
    *   **Request Body**:
        ```json
        {
            "body": "This is my new chirp!"
        }
        ```
    *   **Response**: `201 Created` with the new chirp's details.
*   `GET /api/chirps`
    *   **Description**: Retrieves all chirps, optionally filtered by `author_id` and sorted by `created_at`.
    *   **Query Parameters**:
        *   `author_id` (optional): Filter chirps by a specific user ID.
        *   `sort` (optional): Sort order for chirps. Can be `asc` (default) or `desc`.
    *   **Response**: `200 OK` with an array of chirps.
*   `GET /api/chirps/{chirpID}`
    *   **Description**: Retrieves a single chirp by its ID.
    *   **URL Parameters**: `chirpID` (UUID of the chirp).
    *   **Response**: `200 OK` with the chirp's details, or `404 Not Found` if the chirp does not exist.
*   `DELETE /api/chirps/{chirpID}`
    *   **Description**: Deletes a chirp by its ID. Requires a valid JWT in the Authorization header, and the user must be the author of the chirp.
    *   **Request Headers**: `Authorization: Bearer <JWT>`
    *   **URL Parameters**: `chirpID` (UUID of the chirp).
    *   **Response**: `204 No Content`.

### Webhooks

*   `POST /api/polka/webhooks`
    *   **Description**: Endpoint for Polka webhooks, specifically for upgrading users to Chirpy Red. Requires a valid API key in the Authorization header.
    *   **Request Headers**: `Authorization: ApiKey <POLKA_KEY>`
    *   **Request Body**:
        ```json
        {
            "event": "user.upgraded",
            "data": {
                "user_id": "uuid_of_the_user"
            }
        }
        ```
    *   **Response**: `204 No Content`.

