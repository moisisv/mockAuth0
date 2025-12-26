const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Configuration
const CONFIG = {
  domain: process.env.AUTH0_DOMAIN || "localhost:9999",
  issuer: process.env.AUTH0_ISSUER || "http://localhost:9999/",
  audience: process.env.AUTH0_AUDIENCE || "http://localhost:9999/api/v2/",
  secret:
    process.env.JWT_SECRET || "mock-auth0-secret-key-change-in-production",
  tokenExpiry: process.env.TOKEN_EXPIRY || "24h",
};

// Hardcoded users database
const USERS = [
  {
    user_id: "auth0|user1",
    email: "user1@example.com",
    password: "password123",
    name: "Test User 1",
    nickname: "user1",
    picture: "https://via.placeholder.com/150",
    email_verified: true,
    user_metadata: {
      plan: "basic",
      preferences: { theme: "light" },
    },
    app_metadata: {
      roles: ["user"],
      permissions: ["read:data"],
    },
  },
  {
    user_id: "auth0|user2",
    email: "user2@example.com",
    password: "password456",
    name: "Test User 2",
    nickname: "user2",
    picture: "https://via.placeholder.com/150",
    email_verified: true,
    user_metadata: {
      plan: "premium",
      preferences: { theme: "dark" },
    },
    app_metadata: {
      roles: ["user", "manager"],
      permissions: ["read:data", "write:data"],
    },
  },
  {
    user_id: "auth0|admin",
    email: "admin@example.com",
    password: "admin123",
    name: "Admin User",
    nickname: "admin",
    picture: "https://via.placeholder.com/150",
    email_verified: true,
    roles: ["admin"],
    user_metadata: {
      admin_level: "super",
    },
    app_metadata: {
      roles: ["admin"],
      permissions: ["all"],
    },
  },
];

// Helper function to generate JWT token
function generateToken(user) {
  const payload = {
    sub: user.user_id,
    email: user.email,
    name: user.name,
    nickname: user.nickname,
    picture: user.picture,
    email_verified: user.email_verified,
    iss: CONFIG.issuer,
    aud: CONFIG.audience,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60, // 24 hours
  };

  if (user.roles) {
    payload.roles = user.roles;
  }

  // Add metadata as namespaced claims (Auth0 standard practice)
  // https://auth0.com/docs/secure/tokens/json-web-tokens/create-custom-claims
  const namespace = CONFIG.issuer; // Using issuer as namespace base
  if (user.user_metadata) {
    payload[`${namespace}user_metadata`] = user.user_metadata;
  }
  if (user.app_metadata) {
    payload[`${namespace}app_metadata`] = user.app_metadata;
  }

  return jwt.sign(payload, CONFIG.secret);
}

// Helper function to verify token
function verifyToken(token) {
  try {
    return jwt.verify(token, CONFIG.secret);
  } catch (err) {
    return null;
  }
}

// Auth0 OAuth2 Token endpoint (Password Grant)
app.post("/oauth/token", (req, res) => {
  const { grant_type, username, password, client_id, client_secret, audience } =
    req.body;

  if (grant_type === "password") {
    const user = USERS.find(
      (u) => u.email === username && u.password === password
    );

    if (!user) {
      return res.status(401).json({
        error: "invalid_grant",
        error_description: "Wrong email or password.",
      });
    }

    const accessToken = generateToken(user);
    const idToken = generateToken(user);

    return res.json({
      access_token: accessToken,
      id_token: idToken,
      token_type: "Bearer",
      expires_in: 86400,
    });
  }

  if (grant_type === "client_credentials") {
    // Machine-to-machine token
    const payload = {
      iss: CONFIG.issuer,
      sub: client_id || "mock-client@clients",
      aud: audience || CONFIG.audience,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
      scope: "read:users write:users",
    };

    const token = jwt.sign(payload, CONFIG.secret);

    return res.json({
      access_token: token,
      token_type: "Bearer",
      expires_in: 86400,
    });
  }

  res.status(400).json({
    error: "unsupported_grant_type",
    error_description: "Grant type not supported",
  });
});

// Auth0 UserInfo endpoint
app.get("/userinfo", (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "invalid_token",
      error_description: "Authorization header is required",
    });
  }

  const token = authHeader.substring(7);
  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(401).json({
      error: "invalid_token",
      error_description: "Token is invalid or expired",
    });
  }

  res.json({
    sub: decoded.sub,
    email: decoded.email,
    name: decoded.name,
    nickname: decoded.nickname,
    picture: decoded.picture,
    email_verified: decoded.email_verified,
  });
});

// JWKS endpoint (JSON Web Key Set)
app.get("/.well-known/jwks.json", (req, res) => {
  // For mock purposes, we return a simplified JWKS
  // In production Auth0, this would contain the public keys
  res.json({
    keys: [
      {
        kty: "oct",
        kid: "mock-key-id",
        use: "sig",
        alg: "HS256",
      },
    ],
  });
});

// OpenID Configuration endpoint
app.get("/.well-known/openid-configuration", (req, res) => {
  res.json({
    issuer: CONFIG.issuer,
    authorization_endpoint: `${CONFIG.issuer}authorize`,
    token_endpoint: `${CONFIG.issuer}oauth/token`,
    userinfo_endpoint: `${CONFIG.issuer}userinfo`,
    jwks_uri: `${CONFIG.issuer}.well-known/jwks.json`,
    response_types_supported: ["code", "token", "id_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["HS256", "RS256"],
  });
});

// Management API - Get Users
app.get("/api/v2/users", (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      statusCode: 401,
      error: "Unauthorized",
      message: "Missing or invalid authorization header",
    });
  }

  const token = authHeader.substring(7);
  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(401).json({
      statusCode: 401,
      error: "Unauthorized",
      message: "Invalid token",
    });
  }

  // Return users without passwords, but with metadata
  const safeUsers = USERS.map(({ password, ...user }) => user);
  res.json(safeUsers);
});

// Management API - Get User by ID
app.get("/api/v2/users/:id", (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      statusCode: 401,
      error: "Unauthorized",
      message: "Missing or invalid authorization header",
    });
  }

  const token = authHeader.substring(7);
  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(401).json({
      statusCode: 401,
      error: "Unauthorized",
      message: "Invalid token",
    });
  }

  const user = USERS.find((u) => u.user_id === req.params.id);

  if (!user) {
    return res.status(404).json({
      statusCode: 404,
      error: "Not Found",
      message: "User not found",
    });
  }

  const { password, ...safeUser } = user;
  res.json(safeUser);
});

// Token verification endpoint (custom for testing)
app.post("/verify", (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({
      valid: false,
      error: "Token is required",
    });
  }

  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(401).json({
      valid: false,
      error: "Token is invalid or expired",
    });
  }

  res.json({
    valid: true,
    decoded,
  });
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "mock-auth0" });
});

// Start server
const PORT = process.env.PORT || 9999;
app.listen(PORT, () => {
  console.log(`Mock Auth0 service running on port ${PORT}`);
  console.log(`Domain: ${CONFIG.domain}`);
  console.log(`Issuer: ${CONFIG.issuer}`);
  console.log("\nAvailable users:");
  USERS.forEach((user) => {
    console.log(`  - ${user.email} / ${user.password}`);
  });
});
