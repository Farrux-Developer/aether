# Dockerfile — for Railway, Fly.io, or any container host. Single persistent Node process
# (required: Aether holds live SSE connections + in-memory state — see render.yaml note).

FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-slim AS run
WORKDIR /app
ENV NODE_ENV=production
# Copy the built app and production deps.
COPY --from=build /app/.next ./.next
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/public ./public
COPY --from=build /app/next.config.ts ./next.config.ts
# The host injects PORT; next start reads it. HTTPS is terminated by the platform.
EXPOSE 3000
CMD ["npm", "run", "start"]
