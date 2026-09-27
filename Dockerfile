FROM docker.io/library/node:24.19.0-bookworm@sha256:107ceb6ad85808049dccef12414bf17b08eceb299eaf755c0339dc5fc8958d6b AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run build:node

FROM docker.io/library/node:24.19.0-bookworm@sha256:107ceb6ad85808049dccef12414bf17b08eceb299eaf755c0339dc5fc8958d6b AS runtime

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    ONCEVEIL_SQLITE_PATH=/data/onceveil.sqlite

WORKDIR /app

RUN mkdir -p /data && chown node:node /data

COPY --from=build --chown=node:node /app/.output ./.output

USER node

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD ["node", "--input-type=module", "-e", "const response = await fetch(`http://127.0.0.1:${process.env.PORT ?? '3000'}/ready`, { headers: { Connection: 'close' } }); if (!response.ok) process.exit(1)"]

CMD ["node", ".output/server/index.mjs"]
