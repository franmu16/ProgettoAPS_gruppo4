"""
Elettore (E), Fasi 1, 4 e 6.

Responsabilità:
    Fase 1 : risponde alla challenge FIDO2 del SA;
                         decifra auth_proof (RSA-OAEP) con sk_E.
    Fase 2 : cifra la richiesta (RSA-OAEP) per l'AE;
                         decifra e verifica token e K_pub_cifr (RSA-OAEP).
    Fase 3 : prepara la scheda (cifra voto);
                         cifra il payload (RSA-OAEP) con pk_UE.
    Fase 4 : conserva e valida la ricevuta firmata dall'UE.
    Fase 6 : verifica Merkle Proof e ricevuta (verifica individuale).

Nota FIDO2:
  Il protocollo FIDO2 reale richiede un authenticator hardware. In questa
  simulazione FIDO2 è emulato con RSA challenge/response usando una coppia
  di chiavi dedicata (pk_fido, sk_fido) separata dalla coppia RSA principale
  (pk, sk).

"""

import os

from cryptography.hazmat.primitives import serialization
from Utils.crypto import encrypt_OAEP, sign, verify, hash_SHA256, encrypt_chunked, decrypt_chunked

from Utils.MerkleTree import verify_merkle_proof

# ---------------------------------------------------------------------------
# Voter
# ---------------------------------------------------------------------------

class Voter:
    """Rappresenta un elettore."""

    def __init__(self, voter_id, sk, pk, sk_fido, pk_fido):
        """
        Argomenti:
            voter_id      identificativo anagrafico dell'elettore
            sk / pk       coppia RSA principale (protocollo)
            sk_fido / pk_fido   coppia RSA dedicata FIDO2, separata dalla coppia principale
        """
        self.voter_id = voter_id
        self.sk       = sk
        self.pk       = pk
        self.sk_fido  = sk_fido
        self.pk_fido  = pk_fido

        self._auth_proof = None   # payload (voter_id||r||σ) dal SA
        self._token_id = None
        self._sigma_token = None
        self._pk_enc = None   # K_pub_cifr

        self._ballot_id = None
        self._nonce = None
        self._cv = None
        self._receipt = None

    # ------------------------------------------------------------------
    # Fase 1 – Risposta alla challenge FIDO2
    # ------------------------------------------------------------------

    def respond_to_challenge(self, r):
        """
        Fase 1 lato Elettore (WP2 2.12.2, passo 3):

        Firma la challenge r con sk_fido (simula la verifica biometrica/PIN).
        Restituisce σ_auth = _pss_sign(sk_fido, r).
        """
        return sign(self.sk_fido, r)

    def receive_auth_proof(self, auth_proof_encrypted):
        """
        Fase 1 lato Elettore (WP2 2.12.2, passo 5):

        Decifra auth_proof_encrypted (RSA-OAEP con pk_E dal SA)
        e conserva il payload grezzo (voter_id || r || σ_auth_proof)
        per presentarlo all'AE in Fase 2.

        Restituisce True se la decifratura ha successo.
        """
        try:
            self._auth_proof = decrypt_chunked(self.sk, auth_proof_encrypted)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Fase 2 – Richiesta abilitazione
    # ------------------------------------------------------------------

    def prepare_authorization_request(self, pk_ae):
        """
        Fase 2 lato Elettore (WP2 2.12.3, passo 2):

        Cifra il payload auth_proof grezzo con pk_AE.
        L'AE lo decifrerà e verificherà la firma del SA.
        """
        if self._auth_proof is None:
            raise RuntimeError("auth_proof non disponibile: eseguire prima la Fase 1.")
        # auth_proof = entity_id || challenge(32B) || sigma(256B) > 190B
        return encrypt_chunked(pk_ae, self._auth_proof)

    def receive_ae_response(self, response, pk_ae):
        """
        Fase 2 lato Elettore (WP2 2.12.3, passi 4-5):

        Pacchetto AE:
            4B len(encrypted_token) | encrypted_token | 4B len(encrypted_kpub) | encrypted_kpub

        Dove:
            encrypted_token decifra in: token_id(32B) | sigma_token(256B)
            encrypted_kpub  decifra in: K_pub_cifr PEM | sigma_kpub(256B)

        Verifica entrambe le firme con verify.
        Restituisce True se tutte le verifiche passano.
        """
        #4B len(token) | token | 4B len(kpub) | kpub
        offset = 0
        len_token = int.from_bytes(response[offset: offset + 4], "big")
        offset += 4
        encrypted_token = response[offset: offset + len_token]
        offset += len_token

        len_kpub = int.from_bytes(response[offset: offset + 4], "big")
        offset += 4
        encrypted_kpub = response[offset: offset + len_kpub]

        # Decifratura token tramite chunking
        # AE invia: token_id(32B) || sigma_token(256B)
        try:
            token_payload = decrypt_chunked(self.sk, encrypted_token)
        except Exception:
            return False

        # Convenzione: token_id = primi 32 bytes, sigma = ultimi 256 bytes
        token_id  = token_payload[:32]
        sigma_tok = token_payload[32:]

        if not verify(pk_ae, sigma_tok, token_id):
            return False

        # Decifratura K_pub_cifr tramite chunking
        # AE invia: K_pub_cifr || sigma_kpub(256B)
        try:
            kpub_payload = decrypt_chunked(self.sk, encrypted_kpub)
        except Exception:
            return False

        # Convenzione: sigma = ultimi 256 bytes, K_pub_cifr = tutto il resto
        sigma_kpub = kpub_payload[-256:]
        pk_enc     = kpub_payload[:-256]

        if not verify(pk_ae, sigma_kpub, pk_enc):
            return False

        self._token_id    = token_id
        self._sigma_token = sigma_tok
        self._pk_enc      = serialization.load_pem_public_key(pk_enc)
        return True

    # ------------------------------------------------------------------
    # Fase 3 – Preparazione della scheda
    # ------------------------------------------------------------------

    def prepare_ballot(self, preference, pk_ue):
        """
        Fase 3 lato Elettore (WP2 2.12.4):

          1. cv = encrypt_OAEP(K_pub_cifr, v)        [voto cifrato]
          2. nonce ← os.urandom(32)                   [anti-replay]
          3. ballot_id = SHA-256(token_id || cv || nonce)
          4. payload = 4B len_cv | cv
                     | 2B len_tok | token_id
                     | 4B len_sig | σ_token
                     | 32B nonce
          5. c_trans = encrypt_OAEP(pk_UE, payload)

        Preferenza vuota ("") codifica la scheda bianca (⊥ = 0x00).
        Restituisce c_trans da trasmettere all'UE.
        """
        if self._token_id is None or self._pk_enc is None:
            raise RuntimeError("Token o K_pub_cifr non disponibili.")

        # Passo 2 – cifratura del voto con K_pub_cifr (RSA-OAEP)
        vote_bytes = preference.encode() if preference else b"\x00"
        cv = encrypt_OAEP(self._pk_enc, vote_bytes)

        # Passo 3 – nonce casuale anti-replay
        nonce = os.urandom(32)

        # Passo 4 – ballot_id = SHA-256(token_id || cv || nonce)
        ballot_id = hash_SHA256(self._token_id + cv + nonce)

        # Passo 5 – costruzione del payload della scheda
        tok = self._token_id
        sig = self._sigma_token
        payload = (
            len(cv).to_bytes(4, "big")  + cv +
            len(tok).to_bytes(2, "big") + tok
            + len(sig).to_bytes(4, "big") + sig
            + nonce
        )

        # Passo 5 – cifratura del payload con pk_UE tramite chunking
        # (cv + token + sigma + nonce può superare 190B)
        c_trans = encrypt_chunked(pk_ue, payload)

        # Conserva per Fase 4 e 6
        self._ballot_id = ballot_id
        self._nonce     = nonce
        self._cv        = cv

        return c_trans

    # ------------------------------------------------------------------
    # Fase 4 – Validazione ricevuta
    # ------------------------------------------------------------------

    def validate_receipt(self, receipt, pk_ue):
        """
        Fase 4 lato Elettore (WP2 2.12.5):

        Verifica receipt = _sign(sk_UE, ballot_id || nonce).
        Conserva la ricevuta se la verifica ha successo.
        """
        if self._ballot_id is None or self._nonce is None:
            return False
        if verify(pk_ue, receipt, self._ballot_id + self._nonce):
            self._receipt = receipt
            return True
        return False

    # ------------------------------------------------------------------
    # Fase 6 – Verifica individuale
    # ------------------------------------------------------------------

    def verify_inclusion(self, proof: list[tuple[str, bytes]], root, sigma_root, pk_ue):
        """
        Fase 6 lato Elettore (WP2 2.12.7):

          i.   Verifica σ_root = _sign(sk_UE, root) con pk_UE.
          ii.  Calcola la foglia L = ballot_id (calcolata in Fase 3).
          iii. Verifica Merkle Proof: verify_merkle_proof() da merkle.py.
          iv.  Verifica ricevuta: _sign(sk_UE, ballot_id || nonce).

        Restituisce True solo se tutti e quattro i controlli passano.
        """
        # i. Verifica firma sulla Merkle Root
        if not verify(pk_ue, sigma_root, root):
            return False

        # ii-iii. Verifica Merkle Proof (logica da merkle.py)
        if self._ballot_id is None:
            return False
        if not verify_merkle_proof(self._ballot_id, proof, root):
            return False

        # iv. Verifica ricevuta
        if self._receipt is None:
            return False
        if not verify(pk_ue, self._receipt, self._ballot_id + self._nonce):
            return False

        return True

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    def token_id(self):
        return self._token_id

    def ballot_id(self):
        return self._ballot_id