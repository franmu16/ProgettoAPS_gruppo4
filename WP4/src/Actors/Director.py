"""
Direttore Elettorale (D), Fase 0: Configurazione dell'elezione.

Responsabilità (WP2 2.12.1):
  1. Costruisce il messaggio M con i parametri elettorali.
  2. Firma M con sk_D tramite RSA-PSS.
  3. Cifra M e σ_M con pk_AE tramite RSA-OAEP con chunking.
  4. Restituisce il pacchetto da trasmettere all'AE.

Schema del pacchetto trasmesso:
    4B len(M_encrypted) | M_encrypted | sig_encrypted

dove:
    M_encrypted   = _encrypt_chunked(pk_AE, M_bytes)
    sig_encrypted = _encrypt_chunked(pk_AE, σ_M)
    σ_M           = _sign(sk_D, M_bytes)

"""

import json
import time

from Utils.crypto import sign, encrypt_chunked


def _serialize_M(params: dict) -> bytes:
    """Serializzazione JSON deterministica di M."""
    return json.dumps(params, sort_keys=True, ensure_ascii=True).encode()


class Director:
    """Direttore Elettorale."""

    def __init__(self, sk, pk):
        """
        Argomenti:
            sk – chiave privata RSA del Direttore (2048 bit)
            pk – chiave pubblica RSA del Direttore (distribuita via PKI)
        """
        self.sk = sk
        self.pk = pk


    def configure_election(self, pk_ae, candidates, authorized_offices, t_open=None, duration_seconds=3600):
        """
        Esegue la Fase 0 lato Direttore.

        Argomenti:
            pk_ae              – chiave pubblica AE (estratta dal certificato PKI)
            candidates         – list[str] dei candidati ammessi C
            authorized_offices – list[str] con sedi/uffici autorizzati al voto
            t_open             – timestamp apertura urne (default: adesso)
            duration_seconds   – durata finestra di voto in secondi

        Passi:
            1. Costruisce M = {T_open, T_close, candidates, authorized_offices}
            2. σ_M = sign(sk_D, M)  
            3. M_encrypted = encrypt_OAEP(pk_ae, M_bytes+σ_M)
            4. Pacchetto: 4B len(M_encrypted) | M_encrypted | σ_M
        """
        if t_open is None:
            t_open = time.time()

        # Passo 1 — costruzione di M come unico dizionario JSON
        M_dict = {
            "T_open": t_open,
            "T_close": t_open + duration_seconds,
            "candidates": candidates,
            "authorized_offices": authorized_offices,
        }
        M_bytes = _serialize_M(M_dict)

        # Passo 2 — firma RSA-PSS su M
        sigma_M = sign(self.sk, M_bytes)

        # Passo 3 — cifra (M || sigma_M) con pk_AE tramite chunking
        # Convenzione: la firma è sempre di 256 bytes (chiave 2048 bit)
        # Il destinatario estrae sigma_M = payload[-256:], M = payload[:-256]
        payload = M_bytes + sigma_M
        return encrypt_chunked(pk_ae, payload)