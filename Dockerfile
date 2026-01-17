# Use Debian-based GCC image (NOT Alpine)
FROM gcc:13

# Install ImageMagick with full delegates (PNG/JPEG)
RUN apt-get update && apt-get install -y imagemagick libjpeg-dev libpng-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source files
COPY . .

# Compile the server
RUN gcc -std=gnu99 -DCBC=1 src/*.c -Iinclude -lssl -lcrypto -lm -o stego_server

# Expose port (Render will map dynamically)
EXPOSE 8080

# Run the server
CMD ["./stego_server"]
