
FROM debian:stretch

# Install build dependencies
# We need to update sources because stretch is archived
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
    libffi-dev \
    tk-dev

# 1. Compile OpenSSL 1.0.2u with all legacy protocols enabled
WORKDIR /usr/src
RUN wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz && \
    tar xzf openssl-1.0.2u.tar.gz && \
    cd openssl-1.0.2u && \
    ./config --prefix=/opt/openssl-1.0.2u --openssldir=/opt/openssl-1.0.2u shared zlib enable-ssl2 enable-ssl3 enable-weak-ssl-ciphers && \
    make && \
    make install

# Update linker path
RUN echo "/opt/openssl-1.0.2u/lib" > /etc/ld.so.conf.d/openssl-1.0.2u.conf && ldconfig

# 2. Compile Python 3.9 linked to our custom OpenSSL
# Python 3.10+ removes support for OpenSSL < 1.1.1, so we stick to 3.9
WORKDIR /usr/src
RUN wget https://www.python.org/ftp/python/3.9.18/Python-3.9.18.tgz && \
    tar xzf Python-3.9.18.tgz && \
    cd Python-3.9.18 && \
    # Point to our custom OpenSSL
    LDFLAGS="-L/opt/openssl-1.0.2u/lib -Wl,-rpath,/opt/openssl-1.0.2u/lib" \
    CPPFLAGS="-I/opt/openssl-1.0.2u/include" \
    ./configure --enable-optimizations --prefix=/opt/python3.9 && \
    make altinstall

# 3. Setup Environment
ENV PATH="/opt/python3.9/bin:/opt/openssl-1.0.2u/bin:$PATH"

# Install application dependencies
RUN python3.9 -m pip install --upgrade pip && \
    python3.9 -m pip install cryptography

# 4. Copy Application Code
WORKDIR /app
COPY pki_gen.py server.py iana_ciphers.py /app/

# Create entrypoint script
RUN echo '#!/bin/bash\n\
    python3.9 pki_gen.py\n\
    python3.9 server.py "$@"\n\
    ' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

EXPOSE 4443

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--protocol", "ALL", "--cipher", "ALL:eNULL"]
