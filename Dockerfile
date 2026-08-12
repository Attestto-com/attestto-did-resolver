FROM node:22-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src/ ./src/
RUN npx tsc

FROM node:22-alpine AS runner

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=builder /app/dist/ ./dist/

# `tsc` emits only .js/.d.ts, and server.ts reads this at runtime from the build
# output. Without this line the read throws and — before SOC-175 — CORS fell
# open to '*'. It now refuses to boot instead, so a missing copy is a failed
# deploy rather than a silent hole.
COPY src/cors-whitelist.json ./dist/

# Bundle trust store (copied before build by deploy script)
COPY trust-store/ ./trust-store/

ENV PORT=8080
ENV TRUST_STORE_PATH=/app/trust-store/countries
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

USER node
CMD ["node", "dist/server.js"]
