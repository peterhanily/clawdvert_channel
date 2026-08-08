FROM node:22-alpine

WORKDIR /app
COPY package.json ./
COPY lib ./lib
COPY server.mjs ./

ENV NODE_ENV=production \
    RELAY_BIND=0.0.0.0 \
    RELAY_START_PORT=3478 \
    RELAY_LANES=6 \
    HEALTH_PORT=8080

EXPOSE 3478-3483/udp 8080/tcp
VOLUME ["/data"]
USER node
CMD ["node", "server.mjs"]

