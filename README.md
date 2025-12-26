# Mock Auth0 Service

A dockerized mock Auth0 service for pipeline testing with hardcoded users and full JWT token support.

## Features

- ✅ OAuth2 token generation (password & client_credentials grants)
- ✅ JWT token validation and verification
- ✅ UserInfo endpoint
- ✅ JWKS endpoint
- ✅ OpenID Configuration endpoint
- ✅ Management API (get users)
- ✅ Hardcoded test users
- ✅ Docker ready

## Quick Start

### Using Docker Compose

```bash
# Build and start the service
docker-compose up -d

# Check logs
docker-compose logs -f

# Stop the service
docker-compose down
```

### Using Docker

```bash
# Build the image
docker build -t mock-auth0 .

# Run the container
docker run -p 3000:3000 --name mock-auth0 mock-auth0

# Stop and remove
docker stop mock-auth0 && docker rm mock-auth0
```

### Local Development

```bash
# Install dependencies
npm install

# Start the server
npm start

# Or use nodemon for development
npm run dev
```

## Hardcoded Users

The service comes with three pre-configured users:

| Email             | Password    | Role  |
| ----------------- | ----------- | ----- |
| user1@example.com | password123 | user  |
| user2@example.com | password456 | user  |
| admin@example.com | admin123    | admin |

## API Endpoints

### 1. Get Token (Login)

**POST** `/oauth/token`

```bash
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "username": "user1@example.com",
    "password": "password123",
    "audience": "http://localhost:3000/api"
  }'
```

Response:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

### 2. Get User Info

**GET** `/userinfo`

```bash
curl http://localhost:3000/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Response:

```json
{
  "sub": "auth0|user1",
  "email": "user1@example.com",
  "name": "Test User 1",
  "nickname": "user1",
  "picture": "https://via.placeholder.com/150",
  "email_verified": true
}
```

### 3. Verify Token

**POST** `/verify`

```bash
curl -X POST http://localhost:3000/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_ACCESS_TOKEN"}'
```

Response:

```json
{
  "valid": true,
  "decoded": {
    "sub": "auth0|user1",
    "email": "user1@example.com",
    ...
  }
}
```

### 4. Get All Users (Management API)

**GET** `/api/v2/users`

```bash
curl http://localhost:3000/api/v2/users \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 5. Get User by ID (Management API)

**GET** `/api/v2/users/:id`

```bash
curl http://localhost:3000/api/v2/users/auth0|user1 \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 6. OpenID Configuration

**GET** `/.well-known/openid-configuration`

```bash
curl http://localhost:3000/.well-known/openid-configuration
```

### 7. JWKS

**GET** `/.well-known/jwks.json`

```bash
curl http://localhost:3000/.well-known/jwks.json
```

### 8. Health Check

**GET** `/health`

```bash
curl http://localhost:3000/health
```

## Environment Variables

| Variable       | Default                   | Description           |
| -------------- | ------------------------- | --------------------- |
| PORT           | 3000                      | Server port           |
| AUTH0_DOMAIN   | localhost:3000            | Auth0 domain          |
| AUTH0_ISSUER   | http://localhost:3000/    | Token issuer          |
| AUTH0_AUDIENCE | http://localhost:3000/api | Token audience        |
| JWT_SECRET     | mock-auth0-secret-key...  | JWT signing secret    |
| TOKEN_EXPIRY   | 24h                       | Token expiration time |

## Integration with Your App

### Configuration

Point your application to use the mock Auth0 service:

```javascript
// Example for auth0-js
const auth0 = new auth0.WebAuth({
  domain: "localhost:3000",
  clientID: "mock-client-id",
  audience: "http://localhost:3000/api",
  redirectUri: "http://localhost:8080/callback",
  responseType: "token id_token",
  scope: "openid profile email",
});
```

### Docker Network

If your app is also dockerized, add it to the same network:

```yaml
services:
  your-app:
    image: your-app:latest
    environment:
      - AUTH0_DOMAIN=mock-auth0:3000
      - AUTH0_ISSUER=http://mock-auth0:3000/
    networks:
      - app-network
    depends_on:
      - mock-auth0

  mock-auth0:
    build: ./mock-auth0
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
```

## Testing Examples

### Node.js / JavaScript

```javascript
const axios = require("axios");

// Login
const loginResponse = await axios.post("http://localhost:3000/oauth/token", {
  grant_type: "password",
  username: "user1@example.com",
  password: "password123",
});

const { access_token } = loginResponse.data;

// Get user info
const userInfo = await axios.get("http://localhost:3000/userinfo", {
  headers: { Authorization: `Bearer ${access_token}` },
});

console.log(userInfo.data);
```

### Python

```python
import requests

# Login
response = requests.post('http://localhost:3000/oauth/token', json={
    'grant_type': 'password',
    'username': 'user1@example.com',
    'password': 'password123'
})

access_token = response.json()['access_token']

# Get user info
user_info = requests.get(
    'http://localhost:3000/userinfo',
    headers={'Authorization': f'Bearer {access_token}'}
)

print(user_info.json())
```

### cURL

```bash
# Login and save token
TOKEN=$(curl -s -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"password","username":"user1@example.com","password":"password123"}' \
  | jq -r '.access_token')

# Use token
curl http://localhost:3000/userinfo \
  -H "Authorization: Bearer $TOKEN"
```

## CI/CD Pipeline Example

### GitHub Actions

```yaml
name: Test with Mock Auth0

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      mock-auth0:
        image: mock-auth0:latest
        ports:
          - 3000:3000
        options: >-
          --health-cmd "wget --quiet --tries=1 --spider http://localhost:3000/health || exit 1"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v2

      - name: Wait for Mock Auth0
        run: |
          timeout 30 bash -c 'until curl -f http://localhost:3000/health; do sleep 1; done'

      - name: Run tests
        env:
          AUTH0_DOMAIN: localhost:3000
          AUTH0_ISSUER: http://localhost:3000/
        run: npm test
```

## Customizing Users

Edit the `USERS` array in `server.js`:

```javascript
const USERS = [
  {
    user_id: "auth0|custom1",
    email: "custom@example.com",
    password: "mypassword",
    name: "Custom User",
    nickname: "custom",
    picture: "https://example.com/avatar.jpg",
    email_verified: true,
    roles: ["admin", "user"],
  },
];
```

## Security Notes

⚠️ **This is a mock service for testing only!**

- Uses symmetric JWT signing (HS256) instead of asymmetric (RS256)
- Passwords stored in plain text
- No rate limiting
- No proper JWKS implementation
- Simple secret key

**Never use this in production!**

## Author

Moisis Vafeiadis <moisisv@gmail.com>

## License

MIT
