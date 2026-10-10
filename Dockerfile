FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY rules ./rules
COPY data ./data
COPY public ./public
COPY tsconfig.json ./
# Run as the unprivileged user that ships with the image
USER node
EXPOSE 8080
# Binds 0.0.0.0 only inside the container; publish the port to localhost on the host:
#   docker run -p 127.0.0.1:8080:8080 -e SENTINEL_API_KEY=... sentinel-lite
CMD ["npx", "tsx", "src/cli.ts", "serve", "--host", "0.0.0.0", "--port", "8080"]
