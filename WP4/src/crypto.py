"""
Modulo contenente le primitive crittografiche.

Primitive implementate:
    - Generazione chiavi RSA
    - Cifratura/Decifratura RSA-OAEP
    - Firma/Verifica RSA-PSS
    - Hashing SHA-256
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes


def generate_keys(size):
    """
    Genera una coppia di chiavi RSA.

    :param size: dimensione della chiave in bit (minimo 2048)
    :returns: tupla (private_key, public_key)
    :raises ValueError: se size < 2048
    """
    if size < 2048:
        raise ValueError("La chiave deve essere almeno di 2048 bit")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
    )
    return private_key, private_key.public_key()


def encrypt_OAEP(public_key, plaintext):
    """
    Cifra un messaggio con RSA-OAEP usando SHA-256.

    :param public_key: chiave pubblica RSA del destinatario
    :param plaintext: messaggio in chiaro (bytes)
    :returns: testo cifrato (bytes)
    :raises TypeError: se plaintext non è bytes
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("Il messaggio deve essere in bytes")
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_OAEP(private_key, ciphertext):
    """
    Decifra un testo cifrato con RSA-OAEP usando SHA-256.

    :param private_key: chiave privata RSA del destinatario
    :param ciphertext: testo cifrato (bytes)
    :returns: messaggio in chiaro (bytes)
    :raises TypeError: se ciphertext non è bytes
    :raises ValueError: se il ciphertext è corrotto o il padding non è valido
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("Il ciphertext deve essere in bytes")
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    except ValueError:
        raise ValueError(
            "Decifratura fallita: ciphertext corrotto o padding non valido"
        )
    except Exception as e:
        raise RuntimeError(f"Errore durante la decifratura: {e}")


def sign(private_key, m):
    """
    Firma un messaggio con RSA-PSS usando SHA-256.

    :param private_key: chiave privata RSA del firmatario
    :param m: messaggio da firmare (bytes)
    :returns: firma digitale (bytes)
    :raises TypeError: se m non è bytes
    """
    if not isinstance(m, bytes):
        raise TypeError("Il messaggio deve essere in bytes")
    signature = private_key.sign(
        m,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify(public_key, signature, message):
    """
    Verifica la firma digitale RSA-PSS su un messaggio.

    :param public_key: chiave pubblica RSA del firmatario
    :param signature: firma da verificare (bytes)
    :param message: messaggio originale (bytes)
    :returns: True se la firma è valida, False se non valida
    :raises TypeError: se message non è bytes
    :raises RuntimeError: in caso di errore inatteso
    """
    if not isinstance(message, bytes):
        raise TypeError("Il messaggio deve essere in bytes")
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        raise RuntimeError(f"Errore durante la verifica: {e}")


def hash_SHA256(message):
    """
    Calcola il digest SHA-256 di un messaggio.

    :param message: messaggio da hashare (bytes)
    :returns: digest SHA-256 di 256 bit (bytes)
    :raises TypeError: se message non è bytes
    """
    if not isinstance(message, bytes):
        raise TypeError("Il messaggio deve essere in bytes")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return digest.finalize()

def encrypt_chunked(public_key, plaintext):
    """
    Cifra un messaggio di dimensione arbitraria con RSA-OAEP
    suddividendolo in blocchi da CHUNK_SIZE byte.

    Formato output:
        2B num_blocchi | (4B len_blocco | blocco_cifrato) * num_blocchi

    :param public_key: chiave pubblica RSA del destinatario
    :param plaintext: messaggio in chiaro (bytes)
    :returns: messaggio cifrato a blocchi (bytes)
    :raises TypeError: se plaintext non è bytes
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("Il messaggio deve essere in bytes")

    CHUNK_SIZE = 190
    chunks = [
        plaintext[i:i + CHUNK_SIZE]
        for i in range(0, len(plaintext), CHUNK_SIZE)
    ]

    result = len(chunks).to_bytes(2, 'big')
    for chunk in chunks:
        encrypted_chunk = encrypt_OAEP(public_key, chunk)
        result += len(encrypted_chunk).to_bytes(4, 'big') + encrypted_chunk

    return result


def decrypt_chunked(private_key, data):
    """
    Decifra un messaggio cifrato con encrypt_chunked.

    :param private_key: chiave privata RSA del destinatario
    :param data: messaggio cifrato a blocchi (bytes)
    :returns: messaggio in chiaro riassemblato (bytes)
    :raises TypeError: se data non è bytes
    :raises ValueError: se il formato del messaggio non è valido
    """
    if not isinstance(data, bytes):
        raise TypeError("Il messaggio deve essere in bytes")

    try:
        num_chunks = int.from_bytes(data[:2], 'big')
        offset = 2
        result = b''

        for _ in range(num_chunks):
            chunk_len = int.from_bytes(data[offset:offset + 4], 'big')
            offset += 4
            encrypted_chunk = data[offset:offset + chunk_len]
            offset += chunk_len
            result += decrypt_OAEP(private_key, encrypted_chunk)

        return result
    except ValueError as e:
        raise ValueError(f"Decifratura chunked fallita: {e}")
    except Exception as e:
        raise RuntimeError(f"Errore durante la decifratura chunked: {e}")