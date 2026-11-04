# The image the Agent Lab builds, straight from this repository at a pinned
# commit (affinidi-lab, infra/agent-services/compose.yaml).
# No build step: Node 22.18+ runs the TypeScript directly.
FROM node:22-slim

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY public ./public

# DATA_DIR holds the DID log and its signing keys. A Docker named volume takes
# this directory's owner when first created, so the server can write it.
RUN mkdir /data && chown node:node /data
ENV DATA_DIR=/data PORT=8080
USER node
EXPOSE 8080

CMD ["node", "src/server.ts"]
