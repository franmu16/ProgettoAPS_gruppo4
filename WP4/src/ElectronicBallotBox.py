"""
Urna Elettronica (UE), Fasi 4, 5 e supporto alla Fase 6.

Responsabilità (WP2 2.12.5, 2.12.6, 2.12.7):
  Fase 4 : riceve la scheda cifrata dall'elettore (c_trans);
             decifra con sk_UE tramite RSA-OAEP;
             verifica nonce (anti-replay);
             verifica sigma_token tramite pk_AE (RSA-PSS);
             calcola ballot_id = H(token_id || cv || nonce);
             registra (token_id → {cv, ballot_id, nonce});
             emette ricevuta = sign(sk_UE, ballot_id || nonce).

  Fase 5 : al sopraggiungere di T_close, riceve K_priv_cifr cifrata da AE;
             decifra le schede con K_priv_cifr;
             valida le preferenze rispetto a C;
             costruisce il Merkle Tree (foglie = ballot_id, shuffle incluso);
             firma la radice con sk_UE;
             pubblica il verbale firmato;
             cancella K_priv_cifr dalla memoria.

  Fase 6 : genera Merkle Proof per un dato token_id (richiesta individuale).

Nota: tutti i messaggi hanno dimensione < 150 byte.
      Si usa direttamente RSA-OAEP senza chunking.
      La scheda bianca è rappresentata da cv = b"\x00" (WP2 2.12.4).
"""

import gc
import json
import random

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from crypto import decrypt_OAEP, sign, verify, hash_SHA256, decrypt_chunked
from MerkleTree import build_merkle_tree, generate_merkle_proof


class ElectronicBallotBox:
    """
    Urna Elettronica.

    Gestisce le Fasi 4, 5 e il supporto alla Fase 6 del protocollo WP2.
    """

    def __init__(self, sk_ue, pk_ue, pk_ae, candidates):
        """
        Argomenti:
            sk_ue       chiave privata RSA dell'UE (per decifratura e firma)
            pk_ue       chiave pubblica RSA dell'UE (distribuita via PKI)
            pk_ae       chiave pubblica AE (per verifica sigma_token)
            candidates  lista C dei candidati legittimi (da Fase 0)
        """
        self.sk_ue = sk_ue
        self.pk_ue = pk_ue
        self.pk_ae = pk_ae
        # Includi scheda bianca (WP2 2.12.4)
        self.candidates = set(candidates) | {"\x00"}

        # Registro schede: token_id (bytes) → {"cv": bytes, "ballot_id": bytes, "nonce": bytes}
        # Politica di sovrascrittura (WP2 2.12.5 — modifica voto)
        self._registry: dict[bytes, dict] = {}

        # Registro nonce già visti — anti-replay (WP2 2.12.5 passo 3b)
        self._seen_nonces: set[bytes] = set()

        # Stato post-scrutinio
        self._merkle_tree: list[list[bytes]] | None = None
        self._merkle_root = None
        self._sigma_root = None
        self._tally: dict[str, int] | None = None
        self._verbale = None
        self._sigma_verbale = None

        # Ordine delle foglie nel Merkle Tree (post-shuffle) per generare prove
        self._leaf_order: list[bytes] | None = None

    # ------------------------------------------------------------------
    # Fase 4 – Ricezione e registrazione della scheda
    # ------------------------------------------------------------------

    def receive_ballot(self, c_trans: bytes) -> bytes | None:
        """
        Fase 4 lato UE (WP2 2.12.5).

        Decifra c_trans con sk_UE (RSA-OAEP); verifica nonce e σ_token;
        calcola ballot_id; registra la scheda; restituisce la ricevuta firmata.

        Formato payload (costruito da Voter.prepare_ballot):
            4B len_cv | cv | 2B len_tok | token_id  | 4B len_sig | σ_token | 32B nonce

        Restituisce la ricevuta (bytes) se tutti i controlli passano, None altrimenti.
        """
        # Passo a – decifratura tramite chunking del payload (WP2 2.12.5 passo 3a)
        # (cv + token + sigma + nonce può superare 190B)
        try:
            payload = decrypt_chunked(self.sk_ue, c_trans)
        except Exception:
            return None

        # Parsing del payload
        offset = 0

        len_cv = int.from_bytes(payload[offset: offset + 4], "big")
        offset += 4
        cv = payload[offset: offset + len_cv]
        offset += len_cv

        len_tok = int.from_bytes(payload[offset: offset + 2], "big")
        offset += 2
        token_id = payload[offset: offset + len_tok]
        offset += len_tok

        len_sig = int.from_bytes(payload[offset: offset + 4], "big")
        offset += 4
        sigma_token = payload[offset: offset + len_sig]
        offset += len_sig

        nonce = payload[offset: offset + 32]

        # Passo b – verifica nonce anti-replay (WP2 2.12.5 passo 3b)
        if nonce in self._seen_nonces:
            return None

        # Passo c – verifica sigma_token con pk_AE (RSA-PSS, WP2 2.12.5 passo 3c)
        if not verify(self.pk_ae, sigma_token, token_id):
            return None

        # Passo d – calcolo ballot_id (WP2 2.12.5 passo 3d)
        ballot_id = hash_SHA256(token_id + cv + nonce)

        # Passo e – registrazione con politica di sovrascrittura
        self._registry[token_id] = {
            "cv": cv,
            "ballot_id": ballot_id,
            "nonce": nonce,
        }
        self._seen_nonces.add(nonce)

        # Passo f – emissione ricevuta firmata (WP2 2.12.5 passo 3d / Fase 4 passo 4)
        receipt = sign(self.sk_ue, ballot_id + nonce)
        return receipt

    # ------------------------------------------------------------------
    # Fase 5 – Scrutinio e pubblicazione
    # ------------------------------------------------------------------

    def close_and_tally(self, k_priv_cifr_encrypted):
        """
        Fase 5 lato UE (WP2 2.12.6).

        Argomenti:
            k_priv_cifr_encrypted – encrypt_OAEP(pk_UE, K_priv_cifr_pem)

        Passi:
          1. Decifra K_priv_cifr con sk_UE (RSA-OAEP).
          2. Decifra ogni cv con K_priv_cifr e valida v ∈ C.
          3. Costruisce il Merkle Tree (foglie = ballot_id, shuffle preventivo).
          4. Firma la radice: sigma_root = sign(sk_UE, root).
          5. Compila e firma il verbale.
          6. Cancella K_priv_cifr dalla memoria.

        Restituisce: 4B len(verbale_json) | verbale_json | sigma_verbale
        """
        # Passo 1 – decifratura di K_priv_cifr tramite chunking (WP2 2.12.6 passo 1)
        # (K_priv_cifr PEM ~1700B >> 190B)
        try:
            k_priv_cifr = decrypt_chunked(self.sk_ue, k_priv_cifr_encrypted)
            k_priv_cifr: RSAPrivateKey = serialization.load_pem_private_key(
                k_priv_cifr, password=None
            )
        except Exception as exc:
            raise RuntimeError("Impossibile decifrare K_priv_cifr.") from exc

        # Passo 2 – decifratura e validazione delle schede (WP2 2.12.6 passo 2)
        tally: dict[str, int] = {}
        valid_entries: list[dict] = []

        for token_id, record in self._registry.items():
            vote = "__scheda_nulla__"  # Default se la decifratura o la validazione falliscono
            
            try:
                vote_bytes = decrypt_OAEP(k_priv_cifr, record["cv"])
                decoded_vote = vote_bytes.decode() if vote_bytes != b"\x00" else "\x00"
                
                if decoded_vote in self.candidates:
                    vote = decoded_vote
            except Exception:
                pass  # Mantiene il flag '__scheda_nulla__' senza scartare la foglia

            # Aggiorna il conteggio dei voti
            tally[vote] = tally.get(vote, 0) + 1
            
            # Inserisce SEMPRE l'elemento per il Merkle Tree
            valid_entries.append({
                "token_id": token_id,
                "cv": record["cv"],
                "ballot_id": record["ballot_id"],
                "nonce": record["nonce"],
                "vote": vote,
            })

        self._tally = tally

        # Passo 3 – costruzione Merkle Tree con shuffle (WP2 2.12.6 passo 3)
        if not valid_entries:
            raise RuntimeError("Nessuna scheda valida: impossibile costruire il Merkle Tree.")

        random.shuffle(valid_entries)
        leaves = [e["ballot_id"] for e in valid_entries]
        self._leaf_order = leaves

        root, tree = build_merkle_tree(leaves)
        self._merkle_tree = tree
        self._merkle_root = root

        # Passo 4 – firma della radice (WP2 2.12.6 passo 3)
        self._sigma_root = sign(self.sk_ue, root)

        # Passo 5 – compilazione e firma del verbale (WP2 2.12.6 passo 4)
        token_ids_hex = [e["token_id"].hex() for e in valid_entries]
        verbale_dict = {
            "risultato": {
                (k if k != "\x00" else "__scheda_bianca__"): v
                for k, v in tally.items()
            },
            "merkle_root": root.hex(),
            "num_schede": len(valid_entries),
            "token_ids": token_ids_hex,
        }
        verbale_json = json.dumps(verbale_dict, sort_keys=True, ensure_ascii=True).encode()
        sigma_verbale = sign(self.sk_ue, verbale_json)
        self._verbale = verbale_json
        self._sigma_verbale = sigma_verbale

        # Passo 6 – cancellazione sicura di K_priv_cifr (WP2 2.12.6 passo 5)
        del k_priv_cifr
        gc.collect()

        return len(verbale_json).to_bytes(4, "big") + verbale_json + sigma_verbale

    # ------------------------------------------------------------------
    # Fase 6 – Supporto alla verifica individuale
    # ------------------------------------------------------------------

    def get_merkle_proof(
        self, token_id: bytes
    ) -> tuple[list[tuple[str, bytes]], bytes, bytes] | None:
        """
        Fase 6 lato UE (WP2 2.12.7 passo ii).

        Restituisce (proof, root, sigma_root) se il token_id è registrato
        nel Merkle Tree, None altrimenti.
        """
        if self._merkle_tree is None or self._leaf_order is None:
            return None

        record = self._registry.get(token_id)
        if record is None:
            return None

        ballot_id = record["ballot_id"]

        try:
            leaf_index = self._leaf_order.index(ballot_id)
        except ValueError:
            return None

        proof = generate_merkle_proof(leaf_index, self._merkle_tree)
        return proof, self._merkle_root, self._sigma_root

    # ------------------------------------------------------------------
    # Getter methods per Fase 5 e supporto Fase 6
    # ------------------------------------------------------------------

    def get_merkle_root(self) -> bytes | None:
        """Restituisce la radice del Merkle Tree calcolata in Fase 5."""
        return self._merkle_root

    def get_sigma_root(self) -> bytes | None:
        """Restituisce la firma della radice Merkle calcolata in Fase 5."""
        return self._sigma_root

    def get_tally(self) -> dict[str, int] | None:
        """Restituisce il conteggio dei voti calcolato in Fase 5."""
        return self._tally

    def get_num_valid_ballots(self) -> int:
        """Restituisce il numero di schede registrate."""
        return len(self._registry)