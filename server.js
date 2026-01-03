const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");

const PRIVATE_KEY = fs.readFileSync("./certs/server.key");
const PUBLIC_KEY = fs.readFileSync("./certs/server.cert");

const avatar1 = "https://avataaars.io/?avatarStyle=Circle&topType=ShortHairShortCurly&accessoriesType=Blank&hairColor=Platinum&facialHairType=BeardMajestic&facialHairColor=Blonde&clotheType=BlazerShirt&eyeType=Default&eyebrowType=Default&mouthType=Default&skinColor=Light"
const avatar2 = "https://avataaars.io/?avatarStyle=Circle&topType=LongHairBun&accessoriesType=Kurt&hatColor=Red&hairColor=Auburn&facialHairType=Blank&clotheType=ShirtScoopNeck&clotheColor=PastelYellow&eyeType=Close&eyebrowType=AngryNatural&mouthType=Twinkle&skinColor=Pale"
const avatar3 = "https://avataaars.io/?avatarStyle=Circle&topType=NoHair&accessoriesType=Blank&facialHairType=BeardMedium&facialHairColor=BrownDark&clotheType=ShirtVNeck&clotheColor=PastelBlue&eyeType=Squint&eyebrowType=Default&mouthType=Disbelief&skinColor=Brown"

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

app.get("/", (req, res) => res.send("Mock Auth0 Service is running."));

// Configuration
const CONFIG = {
  domain: process.env.AUTH0_DOMAIN || "localhost:9999",
  issuer: process.env.AUTH0_ISSUER || "https://localhost:9999/",
  audience: process.env.AUTH0_AUDIENCE || "https://localhost:9999/api/v2/",
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
    picture: avatar1,
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
    picture: avatar2,
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
    picture: avatar3,
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

// In-memory storage for authorization codes and PKCE challenges
const authCodes = new Map();
const pkceStore = new Map();

// Helper function to generate random code
const generateCode = () => {
  return crypto.randomBytes(32).toString("base64url");
};

// Helper function to verify PKCE challenge
const verifyPKCE = (codeVerifier, codeChallenge, method = "S256") => {
  if (method === "S256") {
    const hash = crypto
      .createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");
    return hash === codeChallenge;
  } else if (method === "plain") {
    return codeVerifier === codeChallenge;
  }
  return false;
};

// Helper function to generate JWT token
function generateToken(user, audience, nonce) {
  const payload = {
    sub: user.user_id,
    email: user.email,
    name: user.name,
    nickname: user.nickname,
    picture: user.picture,
    email_verified: user.email_verified,
    iss: CONFIG.issuer,
    aud: audience || CONFIG.audience,
    iat: Math.floor(Date.now() / 1000),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60, // 24 hours
  };

  if (nonce) {
    payload.nonce = nonce;
  }

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

  // Sign with RS256 using private key
  return jwt.sign(payload, PRIVATE_KEY, {
    algorithm: "RS256",
    header: {
      kid: "mock-key-id",
    },
  });
}

// Helper function to verify token
function verifyToken(token) {
  try {
    return jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] });
  } catch (err) {
    return null;
  }
}

// OAuth2 Authorization endpoint
app.get("/authorize", (req, res) => {
  const {
    client_id,
    redirect_uri,
    response_type,
    response_mode,
    state,
    nonce,
    scope,
    audience,
    code_challenge,
    code_challenge_method,
    auth0Client,
  } = req.query;

  const { prompt } = req.query;
  if (prompt === "none") {
    const user = USERS.find(u => u.user_id === "auth0|admin") || USERS[0];
    const code = generateCode();
    authCodes.set(code, {
      user,
      client_id,
      redirect_uri,
      scope,
      audience,
      nonce,
      expiresAt: Date.now() + 600000,
    });
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", code);
    if (state) redirectUrl.searchParams.set("state", state);
    console.log("Silent authentication (prompt=none), redirecting to:", redirectUrl.toString());
    return res.redirect(redirectUrl.toString());
  }


  console.log("Authorization request:", {
    client_id,
    redirect_uri,
    response_type,
    scope,
    audience,
  });

  // Validate required parameters
  if (!client_id || !redirect_uri || !response_type) {
    return res
      .status(400)
      .send(
        "Missing required parameters: client_id, redirect_uri, or response_type"
      );
  }

  // Render login page
  const loginPageHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Mock Auth0 Login</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f0f2f5; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center; }
        h1 { margin-bottom: 24px; color: #333; }
        .user-btn { display: block; width: 100%; padding: 12px; margin-bottom: 12px; border: 1px solid #ddd; border-radius: 4px; background: #fff; cursor: pointer; text-align: left; transition: all 0.2s; }
        .user-btn:hover { background: #f9f9f9; border-color: #ccc; }
        .user-info { display: flex; align-items: center; }
        .avatar { width: 32px; height: 32px; border-radius: 50%; margin-right: 12px; background: #eee; }
        .details { display: flex; flex-direction: column; }
        .name { font-weight: 500; font-size: 14px; color: #333; }
        .email { font-size: 12px; color: #666; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Welcome</h1>
        <p>Select a user to continue to <strong>${client_id}</strong></p>
        <form action="/login" method="post">
          <input type="hidden" name="client_id" value="${client_id}">
          <input type="hidden" name="redirect_uri" value="${redirect_uri}">
          <input type="hidden" name="response_type" value="${response_type}">
          <input type="hidden" name="state" value="${state || ""}">
          <input type="hidden" name="nonce" value="${nonce || ""}">
          <input type="hidden" name="scope" value="${scope || ""}">
          <input type="hidden" name="audience" value="${audience || ""}">
          <input type="hidden" name="code_challenge" value="${code_challenge || ""}">
          <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ""
    }">
          
          ${USERS.map(
      (u) => `
            <button type="submit" name="user_id" value="${u.user_id}" class="user-btn">
              <div class="user-info">
                <img src="${u.picture}" class="avatar" alt="${u.name}" />
                <div class="details">
                  <span class="name">${u.name}</span>
                  <span class="email">${u.email}</span>
                </div>
              </div>
            </button>
          `
    ).join("")}
        </form>
      </div>
    </body>
    </html>
  `;

  res.send(loginPageHtml);
});

// Handle login submission
app.post("/login", (req, res) => {
  const {
    user_id,
    client_id,
    redirect_uri,
    response_type,
    state,
    nonce,
    scope,
    audience,
    code_challenge,
    code_challenge_method
  } = req.body;

  const user = USERS.find(u => u.user_id === user_id);

  if (!user) {
    return res.status(400).send("Invalid user selected");
  }

  if (response_type === "code") {
    // Authorization Code Flow
    const code = generateCode();

    // Store the authorization code with associated data
    authCodes.set(code, {
      user,
      client_id,
      redirect_uri,
      scope,
      audience,
      nonce,
      expiresAt: Date.now() + 600000, // 10 minutes
    });

    // Store PKCE challenge if provided
    if (code_challenge) {
      pkceStore.set(code, {
        challenge: code_challenge,
        method: code_challenge_method || "S256",
      });
    }

    // Build redirect URL
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", code);
    if (state) redirectUrl.searchParams.set("state", state);

    console.log("Redirecting to:", redirectUrl.toString());
    return res.redirect(redirectUrl.toString());
  }

  if (
    response_type === "token" ||
    response_type === "id_token" ||
    response_type.includes("token")
  ) {
    // Implicit Flow
    const accessToken = generateToken(user, audience, nonce);
    const idToken = generateToken(user, client_id, nonce);

    const hash = new URLSearchParams();
    if (response_type.includes("token")) {
      hash.set("access_token", accessToken);
      hash.set("token_type", "Bearer");
      hash.set("expires_in", "86400");
    }
    if (response_type.includes("id_token")) {
      hash.set("id_token", idToken);
    }
    if (state) hash.set("state", state);
    if (scope) hash.set("scope", scope);

    const redirectUrl = `${redirect_uri}#${hash.toString()}`;
    console.log("Redirecting to:", redirectUrl);
    return res.redirect(redirectUrl);
  }

  res.status(400).send("Unsupported response_type");
});

// Auth0 OAuth2 Token endpoint
app.post("/oauth/token", (req, res) => {
  const {
    grant_type,
    code,
    code_verifier,
    redirect_uri,
    client_id,
    client_secret,
    username,
    password,
    audience,
    scope,
  } = req.body;

  console.log("Token request:", {
    grant_type,
    code: code ? "present" : "absent",
    client_id,
  });

  // Authorization Code Flow
  if (grant_type === "authorization_code") {
    if (!code) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Code is required",
      });
    }

    const authData = authCodes.get(code);

    if (!authData) {
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Invalid or expired authorization code",
      });
    }

    // Check if code is expired
    if (Date.now() > authData.expiresAt) {
      authCodes.delete(code);
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Authorization code expired",
      });
    }

    // Verify PKCE if it was used
    const pkceData = pkceStore.get(code);
    if (pkceData) {
      if (!code_verifier) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "Code verifier required",
        });
      }

      if (
        !verifyPKCE(code_verifier, pkceData.challenge, pkceData.method)
      ) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Invalid code verifier",
        });
      }

      pkceStore.delete(code);
    }

    // Validate redirect_uri matches
    if (redirect_uri && redirect_uri !== authData.redirect_uri) {
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Redirect URI mismatch",
      });
    }

    // Delete the code (one-time use)
    authCodes.delete(code);

    // Generate tokens
    const accessToken = generateToken(
      authData.user,
      authData.audience || audience,
      authData.nonce
    );
    const idToken = generateToken(authData.user, authData.client_id, authData.nonce);

    console.log("Token issued for user:", authData.user.email);
    console.log("Access token payload:", jwt.decode(accessToken));
    console.log("ID token payload:", jwt.decode(idToken));

    return res.json({
      access_token: accessToken,
      id_token: idToken,
      token_type: "Bearer",
      expires_in: 86400,
      scope: authData.scope || scope || "openid profile email",
    });
  }

  // Resource Owner Password Flow
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

    const accessToken = generateToken(user, audience);
    const idToken = generateToken(user, client_id);

    return res.json({
      access_token: accessToken,
      id_token: idToken,
      token_type: "Bearer",
      expires_in: 86400,
      scope: scope || "openid profile email",
    });
  }

  // Client Credentials Flow
  if (grant_type === "client_credentials") {
    const payload = {
      iss: CONFIG.issuer,
      sub: client_id || "mock-client@clients",
      aud: audience || CONFIG.audience,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
      scope: scope || "read:users write:users",
    };

    const token = jwt.sign(payload, CONFIG.secret);

    return res.json({
      access_token: token,
      token_type: "Bearer",
      expires_in: 86400,
      scope: payload.scope,
    });
  }

  res.status(400).json({
    error: "unsupported_grant_type",
    error_description: `Grant type '${grant_type}' not supported`,
  });
});

// Auth0 UserInfo endpoint
app.get("/userinfo", (req, res) => {
  const authHeader = req.headers.authorization;

  console.log("UserInfo request - Authorization header:", authHeader ? "present" : "missing");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "invalid_token",
      error_description: "Authorization header is required",
    });
  }

  const token = authHeader.substring(7);
  const decoded = verifyToken(token);

  console.log("Token decoded:", decoded ? "success" : "failed");
  if (decoded) {
    console.log("User info for:", decoded.email);
  }

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
    updated_at: new Date().toISOString(),
  });
});

// JWKS endpoint (JSON Web Key Set)
app.get("/.well-known/jwks.json", (req, res) => {
  try {
    const key = crypto.createPublicKey(PUBLIC_KEY);
    const jwk = key.export({ format: "jwk" });

    // Ensure kid matches what we sign with
    jwk.kid = "mock-key-id";
    jwk.use = "sig";
    jwk.alg = "RS256";

    // x5c property is technically optional but often used
    // We would need to strip headers/footers from cert for that

    res.json({
      keys: [jwk],
    });
  } catch (err) {
    console.error("Error generating JWKS:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// OpenID Configuration endpoint
app.get("/.well-known/openid-configuration", (req, res) => {
  const baseUrl = `${req.protocol}://${req.get("host")}`;
  res.json({
    issuer: CONFIG.issuer,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    userinfo_endpoint: `${baseUrl}/userinfo`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    registration_endpoint: `${baseUrl}/oidc/register`,
    scopes_supported: ["openid", "profile", "email", "offline_access"],
    response_types_supported: [
      "code",
      "token",
      "id_token",
      "code token",
      "code id_token",
      "token id_token",
      "code token id_token",
    ],
    response_modes_supported: ["query", "fragment", "form_post"],
    grant_types_supported: [
      "authorization_code",
      "implicit",
      "password",
      "client_credentials",
      "refresh_token",
    ],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: [
      "client_secret_post",
      "client_secret_basic",
    ],
    claims_supported: [
      "sub",
      "email",
      "email_verified",
      "name",
      "nickname",
      "picture",
    ],
    code_challenge_methods_supported: ["S256", "plain"],
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

// Logout endpoint
app.get("/v2/logout", (req, res) => {
  const { returnTo, client_id } = req.query;

  const { prompt } = req.query;
  if (prompt === "none") {
    const user = USERS.find(u => u.user_id === "auth0|admin") || USERS[0];
    const code = generateCode();
    authCodes.set(code, {
      user,
      client_id,
      redirect_uri,
      scope,
      audience,
      nonce,
      expiresAt: Date.now() + 600000,
    });
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", code);
    if (state) redirectUrl.searchParams.set("state", state);
    console.log("Silent authentication (prompt=none), redirecting to:", redirectUrl.toString());
    return res.redirect(redirectUrl.toString());
  }


  if (returnTo) {
    return res.redirect(returnTo);
  }

  res.json({ message: "Logged out successfully" });
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "mock-auth0",
    timestamp: new Date().toISOString(),
  });
});

// Cleanup expired codes periodically
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authCodes.entries()) {
    if (now > data.expiresAt) {
      authCodes.delete(code);
      pkceStore.delete(code);
    }
  }
}, 60000); // Run every minute

// Start server
const https = require("https");
const PORT = process.env.PORT || 9999;
const httpsOptions = {
  key: PRIVATE_KEY,
  cert: PUBLIC_KEY,
};

https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`Mock Auth0 service running on port ${PORT} (HTTPS)`);
  console.log(`Domain: ${CONFIG.domain}`);
  console.log(`Issuer: ${CONFIG.issuer}`);
  console.log("\nAvailable users:");
  USERS.forEach((user) => {
    console.log(`  - ${user.email} / ${user.password}`);
  });
  console.log("\nEndpoints:");
  console.log(`  - Authorization: https://localhost:${PORT}/authorize`);
  console.log(`  - Token: https://localhost:${PORT}/oauth/token`);
  console.log(`  - UserInfo: https://localhost:${PORT}/userinfo`);
});