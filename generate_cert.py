from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import ipaddress

def generate_robust_cert():
    print("Generando certificado SSL robusto con SANs para localhost y 192.168.1.132...")
    
    # 1. Generar clave privada
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Configurar nombres alternativos (SANs)
    # Esto es CRÍTICO para que Chrome/Android acepten el cert (aunque den warning de autoridad)
    alt_names = [
        x509.DNSName(u"localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("192.168.1.132"))
    ]

    # 3. Crear el certificado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Santiago"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Proyecto Produccion Dev"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"192.168.1.132"), # CN principal
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName(alt_names),
        critical=False,
    ).sign(key, hashes.SHA256())

    # 4. Guardar archivos
    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
    print("✅ Certificados generados: cert.pem, key.pem")

if __name__ == "__main__":
    try:
        generate_robust_cert()
    except Exception as e:
        print(f"❌ Error: {e}")
