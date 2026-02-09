
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import datetime
import ipaddress
import os

# Configuration
KEY_SIZE = 2048
VALID_DAYS = 365
COUNTRY = "US"
STATE = "California"
LOCALITY = "San Francisco"
ORG = "Snipher Test Org"

CERTS_DIR = "certs"

def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
    )

def save_key(key, filename):
    with open(os.path.join(CERTS_DIR, filename), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        
def save_cert(cert, filename):
    with open(os.path.join(CERTS_DIR, filename), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def create_cert(subject_name, issuer_name, subject_key, issuer_key, is_ca=False, path_length=None, san_dns=None, san_ip=None):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.public_key(subject_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=VALID_DAYS))

    # Basic Constraints
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=path_length), critical=True,
    )

    # Key Usage
    if is_ca:
        usage = x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            key_cert_sign=True,
            crl_sign=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        )
    else:
        usage = x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        )
    builder = builder.add_extension(usage, critical=True)

    # Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
        critical=False,
    )
    
    # Authority Key Identifier (if not self-signed)
    if issuer_key:
         builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )

    # SANs for leaf
    if san_dns or san_ip:
        san_list = []
        if san_dns:
            for dns in san_dns:
                san_list.append(x509.DNSName(dns))
        if san_ip:
            for ip in san_ip:
                san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    # Sign
    signing_key = issuer_key if issuer_key else subject_key
    cert = builder.sign(
        private_key=signing_key, algorithm=hashes.SHA256(),
    )
    return cert

def main():
    if not os.path.exists(CERTS_DIR):
        os.makedirs(CERTS_DIR)

    print("Generating Root CA...")
    root_key = generate_key()
    save_key(root_key, "root_key.pem")
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, "Snipher Test Root CA"),
    ])
    root_cert = create_cert(root_name, root_name, root_key, None, is_ca=True, path_length=2)
    save_cert(root_cert, "root_cert.pem")

    print("Generating Intermediate CA...")
    inter_key = generate_key()
    save_key(inter_key, "intermediate_key.pem")
    inter_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, "Snipher Test Intermediate CA"),
    ])
    inter_cert = create_cert(inter_name, root_name, inter_key, root_key, is_ca=True, path_length=1)
    save_cert(inter_cert, "intermediate_cert.pem")

    print("Generating Issuing CA...")
    issuing_key = generate_key()
    save_key(issuing_key, "issuing_key.pem")
    issuing_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, "Snipher Test Issuing CA"),
    ])
    issuing_cert = create_cert(issuing_name, inter_name, issuing_key, inter_key, is_ca=True, path_length=0)
    save_cert(issuing_cert, "issuing_cert.pem")

    print("Generating Leaf Certificate...")
    leaf_key = generate_key()
    save_key(leaf_key, "leaf_key.pem")
    leaf_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    leaf_cert = create_cert(
        leaf_name, issuing_name, leaf_key, issuing_key, 
        is_ca=False, 
        san_dns=["localhost", "test.local"], 
        san_ip=["127.0.0.1", "0.0.0.0"]
    )
    save_cert(leaf_cert, "leaf_cert.pem")
    
    # Create full chain
    with open(os.path.join(CERTS_DIR, "fullchain.pem"), "wb") as f:
        f.write(leaf_cert.public_bytes(serialization.Encoding.PEM))
        f.write(issuing_cert.public_bytes(serialization.Encoding.PEM))
        f.write(inter_cert.public_bytes(serialization.Encoding.PEM))
        # Root is usually not in the chain sent by server, but we can include it if needed or just trust it on client
    
    print("PKI Generation Complete. Certs in 'certs/'")

if __name__ == "__main__":
    main()
