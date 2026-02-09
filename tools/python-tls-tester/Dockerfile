FROM debian:stretch

# Install build dependencies
RUN echo "deb http://archive.debian.org/debian stretch main contrib non-free" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security stretch/updates main contrib non-free" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --allow-unauthenticated \
    build-essential \
    checkinstall \
    zlib1g-dev \
    wget \
    curl \
    libffi-dev \
    libsqlite3-dev \
    libreadline-gplv2-dev \
    libncursesw5-dev \
    libssl-dev \
    libgdbm-dev \
    libc6-dev \
    libbz2-dev \
    tk-dev \
    ca-certificates

# 1. Compile OpenSSL 1.0.2u with all legacy protocols enabled (for SSLv2/SSLv3)
WORKDIR /usr/src
RUN wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz && \
    tar xzf openssl-1.0.2u.tar.gz && \
    cd openssl-1.0.2u && \
    ./config --prefix=/opt/openssl-1.0.2u --openssldir=/opt/openssl-1.0.2u shared zlib enable-ssl2 enable-ssl3 enable-weak-ssl-ciphers && \
    make && \
    make install

# 2. Compile OpenSSL 3.3.2 (for TLS 1.3 support)
WORKDIR /usr/src
RUN wget https://www.openssl.org/source/openssl-3.3.2.tar.gz && \
    tar xzf openssl-3.3.2.tar.gz && \
    cd openssl-3.3.2 && \
    ./config --prefix=/opt/openssl-3.3 --openssldir=/opt/openssl-3.3 shared zlib && \
    make && \
    make install

# Update linker paths for both
RUN echo "/opt/openssl-1.0.2u/lib" > /etc/ld.so.conf.d/openssl-1.0.2u.conf && \
    echo "/opt/openssl-3.3/lib64" > /etc/ld.so.conf.d/openssl-3.3.conf && \
    ldconfig

# 3. Compile Python 3.9 linked to OpenSSL 1.0.2u (for legacy protocols)
WORKDIR /usr/src
RUN wget https://www.python.org/ftp/python/3.9.18/Python-3.9.18.tgz && \
    tar xzf Python-3.9.18.tgz && \
    cd Python-3.9.18 && \
    LDFLAGS="-L/opt/openssl-1.0.2u/lib -Wl,-rpath,/opt/openssl-1.0.2u/lib" \
    CPPFLAGS="-I/opt/openssl-1.0.2u/include" \
    ./configure --enable-optimizations --prefix=/opt/python3.9-openssl1 && \
    make altinstall

# 4. Compile Python 3.9 linked to OpenSSL 3.3 (for TLS 1.3)
WORKDIR /usr/src
RUN rm -rf Python-3.9.18 && \
    tar xzf Python-3.9.18.tgz && \
    cd Python-3.9.18 && \
    LDFLAGS="-L/opt/openssl-3.3/lib64 -Wl,-rpath,/opt/openssl-3.3/lib64" \
    CPPFLAGS="-I/opt/openssl-3.3/include" \
    ./configure --enable-optimizations --prefix=/opt/python3.9-openssl3 && \
    make altinstall

# 5. Setup Environment - default to OpenSSL 3.3 version
ENV PATH="/opt/python3.9-openssl3/bin:/opt/openssl-3.3/bin:/opt/openssl-1.0.2u/bin:$PATH"

# Install cryptography for both Python installations
RUN /opt/python3.9-openssl1/bin/python3.9 -m pip install --upgrade pip && \
    /opt/python3.9-openssl1/bin/python3.9 -m pip install cryptography && \
    /opt/python3.9-openssl3/bin/python3.9 -m pip install --upgrade pip && \
    /opt/python3.9-openssl3/bin/python3.9 -m pip install cryptography

# 6. Copy Application Code
WORKDIR /app
COPY pki_gen.py server.py iana_ciphers.py /app/

# Create smart entrypoint script that routes to appropriate Python based on protocol
RUN echo '#!/bin/bash\n\
    \n\
    # Parse arguments to determine which OpenSSL/Python to use\n\
    PYTHON_BIN="/opt/python3.9-openssl3/bin/python3.9"\n\
    \n\
    # Check if protocol is SSLv2 or SSLv3 (requires OpenSSL 1.0.2u)\n\
    for i in "$@"; do\n\
    if [ "$prev_arg" = "--protocol" ]; then\n\
    if [ "$i" = "SSLv2" ] || [ "$i" = "SSLv3" ]; then\n\
    PYTHON_BIN="/opt/python3.9-openssl1/bin/python3.9"\n\
    echo "Using Python linked to OpenSSL 1.0.2u for legacy protocol support"\n\
    else\n\
    echo "Using Python linked to OpenSSL 3.3 for modern protocol support"\n\
    fi\n\
    break\n\
    fi\n\
    prev_arg="$i"\n\
    done\n\
    \n\
    # Generate PKI (only once, reuse certs directory if exists)\n\
    if [ ! -d "certs" ]; then\n\
    echo "Generating PKI..."\n\
    # Use OpenSSL 3 Python for PKI generation (more modern/stable)\n\
    /opt/python3.9-openssl3/bin/python3.9 pki_gen.py\n\
    fi\n\
    \n\
    # Run server with appropriate Python\n\
    exec $PYTHON_BIN server.py "$@"\n\
    ' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

EXPOSE 4443

ENTRYPOINT ["/app/entrypoint.sh"]
