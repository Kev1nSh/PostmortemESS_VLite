FROM node:22-alpine3.24 AS build

WORKDIR /app

RUN apk update && apk upgrade --no-cache

RUN npm install -g pnpm@10.33.0
# Give the non root user ownership of the application directory
RUN chown node:node /app

# Use a non-root user to run our application
USER node

# Copy dependency files as the non-root user
COPY --chown=node:node package.json pnpm-lock.yaml ./

# Install dependencies without modifying the lockfile
RUN pnpm install --frozen-lockfile

# Copy application source as non-root
COPY --chown=node:node . .

# Build the application frontend
RUN pnpm build


## Runtime

FROM nginx:1.29-alpine

# Copy only the compiled frontend.
COPY --from=build --chown=101:101 /app/dist /usr/share/nginx/html

# Custom NGINX configuration.
COPY --chown=101:101 nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]