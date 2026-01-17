# Debian-based GCC image
FROM gcc:13

# Install runtime + build dependencies
RUN apt-get update && apt-get install -y imagemagick libjpeg-dev libpng-dev libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source
COPY . .

# Build (match WSL build exactly)
RUN gcc -std=c99 -D_POSIX_C_SOURCE=200809L -DCBC=1 src/*.c -Iinclude -lssl -lcrypto -lm -o stego_server

EXPOSE 8080

CMD ["./stego_server"]
