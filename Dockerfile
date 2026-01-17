# Use a lightweight Linux base image
FROM alpine:latest

# Install dependencies: GCC, make, ImageMagick, OpenSSL, etc.
RUN apk add --no-cache gcc musl-dev make imagemagick openssl-dev

# Copy your source files
COPY . /app
WORKDIR /app

# Compile the server (adjust if your build command differs)
RUN gcc -std=gnu99 -DCBC=1 src/*.c -Iinclude -lssl -lcrypto -lm -o stego_server

# Expose port 8080
EXPOSE 8080

# Run the server
CMD ["./stego_server"]