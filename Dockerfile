FROM node:22-alpine AS base

WORKDIR /app

# Install dependencies only when needed
FROM base AS deps
RUN apk add --no-cache libc6-compat

COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile

# Copy src/ files
FROM base AS app

COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package.json ./package.json
COPY ./src ./src

FROM app AS runner

ENV NODE_ENV=production

ARG PORT=3000
EXPOSE $PORT

ENV HOST=0.0.0.0

CMD ["yarn", "start"]
