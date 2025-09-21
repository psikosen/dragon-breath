# Build stage
FROM ubuntu:24.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git ca-certificates curl \
    libssl-dev libjsoncpp-dev libhiredis-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Drogon from source (stable)
RUN git clone --depth 1 https://github.com/drogonframework/drogon.git /tmp/drogon \
 && cd /tmp/drogon && mkdir build && cd build \
 && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=OFF -DBUILD_ORM=OFF .. \
 && cmake --build . -j$(nproc) && cmake --install .

WORKDIR /app
COPY . /app
RUN mkdir -p build && cd build && cmake .. && cmake --build . -j$(nproc)

# Runtime stage
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libjsoncpp25 libhiredis0.14 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY --from=build /usr/local/lib /usr/local/lib
COPY --from=build /usr/local/include /usr/local/include
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /app/build/drgn_surreal /srv/drgn_surreal
COPY ./config/config.json /srv/config.json

# Env defaults (override in compose)
ENV SURREAL_URL=http://surrealdb:8000 \
    SURREAL_NS=app \
    SURREAL_DB=dashboard \
    SURREAL_USER=root \
    SURREAL_PASS=root \
    JWT_SECRET=change_me_dev_secret \
    REDIS_HOST=redis \
    REDIS_PORT=6379 \
    REDIS_DB=0

EXPOSE 8080
CMD ["/srv/drgn_surreal", "--config=/srv/config.json"]
