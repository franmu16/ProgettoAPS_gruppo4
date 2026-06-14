"""
Modulo che implementa la Certification Authority (CA).

È responsabile dell'emissione e della verifica dei certificati digitali
per tutti gli attori del sistema.

Responsabilità:
    - Generazione e gestione della propria coppia di chiavi RSA
    - Emissione di certificati digitali X.509 (semplificati) per gli attori
    - Verifica dell'autenticità dei certificati tramite la propria firma
    - Gestione del registro pubblico dei certificati degli attori istituzionali
      (D, SA, AE, UE) — i certificati degli elettori non sono pubblicati
      per preservare il requisito di pseudoanonimato.
"""

from crypto import generate_keys, sign, verify
from cryptography.hazmat.primitives import serialization


class CertificationAuthority:
    
    def __init__(self):
        # Genera la coppia di chiavi della CA
        self._private_key, self.public_key = generate_keys(2048)
        # Registro dei certificati pubblici degli attori istituzionali
        self._registry = {}
    


    def generate_certificate(self, entity_id, public_key):
        """
        Emette un certificato per un'entità.
        Il certificato è un dizionario firmato dalla CA.
        """
        info = {
            "entity_id": entity_id,
            "public_key": public_key
        }
        # Serializza il contenuto per firmarlo
        info_bytes = self._serialize_cert(info)
        signature = sign(self._private_key, info_bytes)
        
        certificate = {
            "entity_id": entity_id,
            "public_key": public_key,
            "signature": signature
        }
        return certificate
    


    def verify_certificate(self, certificate):
        """
        Verifica che un certificato sia stato emesso dalla CA.
        Restituisce True se valido, False altrimenti.
        """
        info = {
            "entity_id": certificate["entity_id"],
            "public_key": certificate["public_key"]
        }
        info_bytes = self._serialize_cert(info)
        return verify(self.public_key, certificate["signature"], info_bytes)
    


    def extract_public_key(self, certificate):
        """
        Estrae la chiave pubblica da un certificato verificato.
        """
        if not self.verify_certificate(certificate):
            raise ValueError("Certificato non valido")
        return certificate["public_key"]
    


    def publish_certificate(self, entity_id, certificate):
        """
        Pubblica il certificato di un attore istituzionale
        nel registro pubblico della PKI.
        """
        if not self.verify_certificate(certificate):
            raise ValueError("Certificato non valido")
        self._registry[entity_id] = certificate
    


    def get_certificate(self, entity_id):
        """
        Recupera il certificato di un attore istituzionale
        dalla PKI. Solleva un'eccezione se non trovato.
        """
        if entity_id not in self._registry:
            raise KeyError(f"Certificato per {entity_id} non trovato")
        return self._registry[entity_id]
    


    def _serialize_cert(self, cert_content):
        """
        Serializza il contenuto del certificato in bytes
        per la firma/verifica.
        """
        pk_bytes = cert_content["public_key"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        entity_bytes = cert_content["entity_id"].encode()
        return entity_bytes + pk_bytes