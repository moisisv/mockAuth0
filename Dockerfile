FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY server.js ./
COPY certs ./certs

# Expose port
EXPOSE 9999

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "const https = require('https'); const options = { hostname: 'localhost', port: 9999, path: '/health', method: 'GET', rejectUnauthorized: false }; const req = https.request(options, (res) => { process.exit(res.statusCode === 200 ? 0 : 1); }); req.on('error', (e) => { process.exit(1); }); req.end();"

# Start the service
CMD ["node", "server.js"]