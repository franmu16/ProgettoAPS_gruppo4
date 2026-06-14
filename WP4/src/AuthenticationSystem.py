"""
Modulo che implementa il Sistema di Autenticazione (SA).

Responsabilità:
    - Registrazione degli elettori tramite FIDO2 (simulato con RSA-PSS)
    - Autenticazione degli elettori tramite challenge/response
    - Rilascio della prova di autenticazione firmata e cifrata

Nota: FIDO2 è simulato tramite challenge/response RSA-PSS.
In un'implementazione reale si userebbe la libreria python-fido2
con hardware dedicato (es. YubiKey, Windows Hello).

Interazioni:
    - Fase 1: autentica l'elettore e rilascia auth_proof
"""

import os
from crypto import generate_keys, sign, verify, encrypt_chunked


class AuthenticationSystem:

    def __init__(self, ca):
        """
        Inizializza il Sistema di Autenticazione.
        Genera la propria coppia di chiavi RSA e si registra nella PKI.

        :param ca: istanza della CertificationAuthority aziendale
        """
        self._private_key, self.public_key = generate_keys(2048)
        self._ca = ca

        # Genera e pubblica il proprio certificato nella PKI
        self._certificate = ca.generate_certificate("SA", self.public_key)
        ca.publish_certificate("SA", self._certificate)

        # Registro degli elettori: entity_id -> pk_FIDO
        # Popolato durante la fase di registrazione FIDO2
        self._registered_voters = {}

        # Registro delle challenge attive: entity_id -> challenge
        # Ogni challenge è monouso e viene eliminata dopo la verifica
        self._active_challenges = {}

    # -------------------------------------------------------------------------
    # REGISTRAZIONE FIDO2
    # -------------------------------------------------------------------------

    def generate_registration_challenge(self, entity_id):
        """
        Fase di registrazione FIDO2 - passo 1.
        Genera una challenge casuale monouso da inviare all'elettore.

        :param entity_id: identificativo dell'elettore
        :returns: challenge casuale di 256 bit (bytes)
        """
        challenge = os.urandom(32) 
        self._active_challenges[entity_id] = challenge
        return challenge

    def complete_registration(self, entity_id, pk_fido, sigma_reg):
        """
        Fase di registrazione FIDO2 - passo 2.
        Verifica la firma sulla challenge e registra la chiave FIDO
        dell'elettore nel proprio registro.

        :param entity_id: identificativo dell'elettore
        :param pk_fido: chiave pubblica FIDO2 dell'elettore
        :param sigma_reg: firma della challenge con sk_FIDO
        :returns: True se la registrazione è andata a buon fine
        :raises ValueError: se la challenge non esiste o la firma non è valida
        """
        if entity_id not in self._active_challenges:
            raise ValueError(f"Nessuna challenge attiva per {entity_id}")

        challenge = self._active_challenges[entity_id]

        if not verify(pk_fido, sigma_reg, challenge):
            raise ValueError("Firma di registrazione non valida")

        # Registra la chiave FIDO e invalida la challenge
        self._registered_voters[entity_id] = pk_fido
        del self._active_challenges[entity_id]
        return True

    # -------------------------------------------------------------------------
    # AUTENTICAZIONE FIDO2
    # -------------------------------------------------------------------------

    def generate_auth_challenge(self, entity_id):
        """
        Fase 1 - passo 2.
        Verifica che l'elettore sia registrato e genera una
        challenge casuale monouso.

        :param entity_id: identificativo dell'elettore
        :returns: challenge casuale di 256 bit (bytes)
        :raises ValueError: se l'elettore non è registrato
        """
        if entity_id not in self._registered_voters:
            raise ValueError(
                f"Elettore {entity_id} non registrato presso il SA"
            )

        challenge = os.urandom(32)  # 256 bit
        self._active_challenges[entity_id] = challenge
        return challenge

    def verify_authentication(self, entity_id, sigma_auth, cert_E):
        """
        Fase 1 - passi 3 e 4.
        Verifica il certificato dell'elettore tramite la CA e
        la firma FIDO2 sulla challenge.

        :param entity_id: identificativo dell'elettore
        :param sigma_auth: firma della challenge con sk_FIDO
        :param cert_E: certificato digitale dell'elettore
        :returns: True se l'autenticazione è valida
        :raises ValueError: se il certificato o la firma non sono validi
        """
        # Verifica il certificato dell'elettore tramite la CA
        if not self._ca.verify_certificate(cert_E):
            raise ValueError("Certificato dell'elettore non valido")

        # Verifica che la challenge sia attiva
        if entity_id not in self._active_challenges:
            raise ValueError(f"Nessuna challenge attiva per {entity_id}")

        challenge = self._active_challenges[entity_id]

        # Recupera pk_FIDO dal registro e verifica la firma
        pk_fido = self._registered_voters[entity_id]
        if not verify(pk_fido, sigma_auth, challenge):
            del self._active_challenges[entity_id]
            raise ValueError("Firma FIDO2 non valida")

        # Challenge monouso: elimina dopo la verifica
        del self._active_challenges[entity_id]
        return True

    def release_auth_proof(self, entity_id, challenge, pk_E):
        """
        Fase 1 - passo 5.
        Rilascia la prova di autenticazione firmata con sk_SA
        e cifrata con pk_E.

        Il messaggio firmato è: entity_id || challenge
        Il messaggio cifrato è: entity_id || challenge || sigma_auth_proof

        :param entity_id: identificativo dell'elettore autenticato
        :param challenge: challenge usata durante l'autenticazione
        :param pk_E: chiave pubblica RSA dell'elettore (per cifrare)
        :returns: auth_proof cifrata con pk_E (bytes)
        """
        # Costruisce il messaggio da firmare
        entity_bytes = entity_id.encode()
        message = entity_bytes + challenge

        # Firma con sk_SA
        sigma_auth_proof = sign(self._private_key, message)

        # Cifra (entity_id || challenge || firma) con pk_E tramite chunking
        # (entity_id + challenge 32B + sigma 256B > 190B)
        payload = entity_bytes + challenge + sigma_auth_proof
        auth_proof = encrypt_chunked(pk_E, payload)
        return auth_proof