
import http.server
import ssl
import socket
import argparse
import sys
import os

# Try to import our cipher mapping
sys.path.append(os.getcwd())
try:
    import iana_ciphers
except ImportError:
    print("Warning: iana_ciphers.py not found. Cipher mapping will not work.")
    iana_ciphers = None

class SimpleHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        
        # Get connection info
        cipher = self.request.cipher()
        protocol = self.request.version()
        
        response = f"Hello from {protocol} using {cipher}\n"
        self.wfile.write(response.encode("utf-8"))

def get_protocol_constant(proto_name):
    # Map string to ssl.PROTOCOL_* constants
    # strict mapping might require setting context.minimum_version / maximum_version
    # for cleaner control, we default to PROTOCOL_TLS and restrict via options/versions
    return ssl.PROTOCOL_TLS

def configure_context(args, context):
    # Set basics
    context.load_cert_chain(certfile="certs/fullchain.pem", keyfile="certs/leaf_key.pem")
    
    # Protocol restriction
    # Note: Providing exact control depends on OpenSSL version and Python version
    if args.protocol == "TLSv1.3":
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
    elif args.protocol == "TLSv1.2":
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
    elif args.protocol == "TLSv1.1":
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_1
            context.maximum_version = ssl.TLSVersion.TLSv1_1
    elif args.protocol == "TLSv1.0":
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1
    elif args.protocol == "SSLv3":
        # Requires system OpenSSL support
        try:
             context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
             context.load_cert_chain(certfile="certs/fullchain.pem", keyfile="certs/leaf_key.pem")
        except AttributeError:
             print("Error: SSLv3 not supported by this Python/OpenSSL installation")
             sys.exit(1)
    elif args.protocol == "SSLv2":
        # Requires system OpenSSL support
        try:
             context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
             context.load_cert_chain(certfile="certs/fullchain.pem", keyfile="certs/leaf_key.pem")
        except AttributeError:
             print("Error: SSLv2 not supported by this Python/OpenSSL installation")
             sys.exit(1)
             
    # Cipher selection
    if args.cipher:
        openssl_cipher = args.cipher
        # Check if it's an IANA name
        if iana_ciphers and args.cipher in iana_ciphers.IANA_TO_OPENSSL:
            openssl_cipher = iana_ciphers.IANA_TO_OPENSSL[args.cipher]
            print(f"Mapped IANA name '{args.cipher}' to OpenSSL string '{openssl_cipher}'")
            
        try:
            context.set_ciphers(openssl_cipher)
        except ssl.SSLError as e:
            # Fallback for specifically this common string if @SECLEVEL is unsupported
            if openssl_cipher == "ALL:eNULL:@SECLEVEL=0":
                print(f"Warning: '{openssl_cipher}' failed (likely unsupported on this OpenSSL version). Trying fallback 'ALL:eNULL'.")
                try:
                    context.set_ciphers("ALL:eNULL")
                except ssl.SSLError as e2:
                    print(f"Error setting fallback cipher 'ALL:eNULL': {e2}")
                    sys.exit(1)
            else:
                print(f"Error setting cipher '{openssl_cipher}': {e}")
                sys.exit(1)
    else:
        # User wants "every available cipher"
        # We try to be as permissive as possible
        try:
            # ALL = all ciphers
            # eNULL = include NULL ciphers (no encryption)
            # @SECLEVEL=0 = allow weak ciphers/keys (OpenSSL 1.1+)
            context.set_ciphers("ALL:eNULL:@SECLEVEL=0")
        except ssl.SSLError as e:
            # Fallback for OpenSSL < 1.1.0 which doesn't support @SECLEVEL
            try:
                 context.set_ciphers("ALL:eNULL")
            except ssl.SSLError as e2:
                 print(f"Warning: Could not set permissive cipher list: {e2}")
                 print("Falling back to default cipher list.")
            
    return context

def main():
    parser = argparse.ArgumentParser(description="Python TLS Test Server")
    parser.add_argument("--port", type=int, default=4443, help="Port to listen on")
    parser.add_argument("--protocol", choices=["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"], required=True, help="TLS Version to force")
    parser.add_argument("--cipher", type=str, help="Cipher suite string (OpenSSL format or IANA name)")
    
    args = parser.parse_args()

    # Create Context
    # We use PROTOCOL_TLS to be compatible with both server-side and client-side (though we wrap server-side)
    # and it allows setting options more freely than PROTOCOL_TLS_SERVER in some versions.
    # However, http.server expects server_side=True in wrap_socket.
    if args.protocol == "SSLv2":
        try:
             context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
        except AttributeError:
             print("Error: SSLv2 not supported by this Python/OpenSSL installation")
             sys.exit(1)
    elif args.protocol == "SSLv3":
        try:
             context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
        except AttributeError:
             print("Error: SSLv3 not supported by this Python/OpenSSL installation")
             sys.exit(1)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)

    # Set security level to 0 to allow weak parameters if supported
    # This is critical for enabling things like anon cyphers, weak keys, or legacy protocols on newer OpenSSL
    try:
        context.security_level = 0
    except AttributeError:
        pass # Older python/openssl might not have this property

    try:
        context.post_handshake_auth = True # For TLS1.3 if needed
    except AttributeError:
        pass # Older OpenSSL/Python doesn't support this
    
    context = configure_context(args, context)
    
    server_address = ("0.0.0.0", args.port)
    httpd = http.server.HTTPServer(server_address, SimpleHandler)
    
    # Wrap socket
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print(f"Serving HTTPS on 0.0.0.0:{args.port}...")
    print(f"Protocol: {args.protocol}")
    print(f"Cipher: {args.cipher if args.cipher else 'Default'}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")

if __name__ == "__main__":
    main()
