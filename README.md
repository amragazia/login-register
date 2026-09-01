# Login Register API

This application is designed specifically for testing purposes as it is intentionally vulnerable. It serves as a practical sandbox for penetration testing and learning web application security concepts.

## Setup Instructions

*   **Environment Configuration:** Create your own `.env` file in the project directory and set a long, private `SECRET_KEY` before running the application.
*   **Run the Backend:** Start the FastAPI server from your terminal using the following command:
    `uv run fastapi dev app/routes.py --env-file .env`.
*   **Run the Frontend:** Open the `app/index.html` file using a local web server. For example, you can use the VS Code Live Server extension to host the page on `http://127.0.0.1:5500`.

## API Features

The application exposes the following endpoints and features:
*   `POST /create-user` to register new accounts.
*   `POST /login` for authenticating users.
*   `GET /home/{username}` to view authenticated user profiles.
*   `GET /home/dashboard` providing an admin-only secure dashboard.
*   `PUT /home/{username}/update` to safely modify an existing user's username or password.
*   `DELETE /home/{username}/delete-user` to permanently remove a user account from the database.
*   `GET /home/{username}/view-users` acting as an admin-only tool to view the entire user database or search for a specific user via query parameters.
*   Passwords are securely stored as salted scrypt hashes.
*   Stateless authentication using JSON Web Tokens (JWT) to protect secure routes and manage sessions.
*   CORS middleware specifically configured to trust and accept cross-origin requests from local frontend servers.

## Security Testing & Adjusting Vulnerabilities

You can manually adjust or introduce vulnerabilities directly from the `routes.py` code to test different exploit scenarios. 

**Example: Enabling IDOR**
To practice Insecure Direct Object Reference (IDOR) attacks, navigate to your protected routes (like `GET /home/{username}`) in `routes.py` and create the vulnerability by commenting out the validation check against the `current_user` (`if username != current_user:`). Removing this authorization check will allow any authenticated user to manipulate the URL parameters and illegally view or modify other users' private database records.