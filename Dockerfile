FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
COPY server.mjs ./
COPY lib ./lib
COPY tools ./tools

USER node
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "server.mjs"]
