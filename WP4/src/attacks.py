"""
Simulazione degli attacchi al protocollo di voto elettronico.

Per ogni attacco vengono mostrati:
    - Descrizione dell'attacco
    - Esito atteso
    - Conferma che la contromisura funziona (✓) o che il limite è reale (✗)

Attacchi simulati:
    1. Replay attack          — reinvio di una scheda intercettata
    2. Token auto-generato    — token firmato con chiave non autorizzata
    3. Certificato contraffatto — MitM sostituisce il certificato del SA
    4. Doppia abilitazione    — AE disonesta emette due token per lo stesso elettore
    5. Modifica scheda        — MitM altera il ciphertext in transito
    6. Collusione AE+UE       — violazione dello pseudoanonimato
    7. UE disonesta           — non sovrascrive, accetta schede multiple
"""

import os
import json
import time

from crypto import generate_keys, sign, encrypt_OAEP, encrypt_chunked, hash_SHA256
from CertificationAuthority import CertificationAuthority as CA
from AuthenticationSystem import AuthenticationSystem as SA
from ElectionAuthority import ElectionAuthority as AE
from Director import Director
from Voter import Voter
from ElectronicBallotBox import ElectronicBallotBox as UE


# =============================================================================
# UTILITÀ
# =============================================================================

def print_header(title):
    print(f"\n{'='*62}")
    print(f"  {title}")
    print(f"{'='*62}")

def print_attack(desc):
    print(f"\n  ⚔  Attacco: {desc}")

def print_ok(msg):
    print(f"      ✓ MITIGATO — {msg}")

def print_fail(msg):
    print(f"      ✗ LIMITE   — {msg}")

def print_step(msg):
    print(f"      → {msg}")

def separatore():
    print(f"  {'─'*60}")


# =============================================================================
# SETUP COMUNE
# =============================================================================

def setup_sistema():
    """Inizializza il sistema con CA, SA, AE, UE e un elettore."""
    ca = CA()
    sa = SA(ca)
    ae = AE(ca)

    sk_dir, pk_dir = generate_keys(2048)
    cert_dir = ca.generate_certificate("Direttore", pk_dir)
    ca.publish_certificate("Direttore", cert_dir)
    director = Director(sk_dir, pk_dir)

    sk_ue, pk_ue = generate_keys(2048)
    cert_ue = ca.generate_certificate("UE", pk_ue)
    ca.publish_certificate("UE", cert_ue)

    # Fase 0
    pk_ae = ca.extract_public_key(ca.get_certificate("AE"))
    payload = director.configure_election(
        pk_ae=pk_ae,
        candidates=["Mario Rossi", "Laura Bianchi", "Giovanni Verdi"],
        authorized_offices=["Roma"],
        t_open=time.time(),
        duration_seconds=3600,
    )
    ae.receive_params(payload, cert_dir)

    ue = UE(
        sk_ue=sk_ue,
        pk_ue=pk_ue,
        pk_ae=ae.public_key,
        candidates=["Mario Rossi", "Laura Bianchi", "Giovanni Verdi"],
    )

    # Elettore alice
    sk_v, pk_v = generate_keys(2048)
    sk_f, pk_f = generate_keys(2048)
    voter = Voter("alice", sk_v, pk_v, sk_f, pk_f)
    cert_E = ca.generate_certificate("alice", pk_v)
    ae.add_voter("alice")

    # Registrazione FIDO2
    ch = sa.generate_registration_challenge("alice")
    sa.complete_registration("alice", pk_f, voter.respond_to_challenge(ch))

    # Autenticazione e abilitazione
    ch = sa.generate_auth_challenge("alice")
    sig = voter.respond_to_challenge(ch)
    sa.verify_authentication("alice", sig, cert_E)
    ap = sa.release_auth_proof("alice", ch, pk_v)
    voter.receive_auth_proof(ap)

    pk_ae2 = ca.extract_public_key(ca.get_certificate("AE"))
    req = voter.prepare_authorization_request(pk_ae2)
    pk_sa = ca.extract_public_key(ca.get_certificate("SA"))
    ae.receive_enablement_request(req, cert_E, pk_sa)
    et = ae.release_token("alice", pk_v)
    ek = ae.release_encryption_key(pk_v)
    resp = len(et).to_bytes(4,"big") + et + len(ek).to_bytes(4,"big") + ek
    voter.receive_ae_response(resp, pk_ae2)

    return ca, sa, ae, ue, voter, cert_E, pk_ue


# =============================================================================
# ATTACCO 1 — REPLAY ATTACK
# =============================================================================

def attacco_replay():
    print_header("ATTACCO 1 — Replay Attack")
    print("  Scenario: il MitM intercetta una scheda valida e la reinvia")
    print("  all'UE per far contare il voto due volte.")
    separatore()

    ca, sa, ae, ue, voter, cert_E, pk_ue = setup_sistema()

    # Elettore vota regolarmente
    c_trans = voter.prepare_ballot("Mario Rossi", pk_ue)
    print_step("Elettore invia scheda legittima all'UE")
    receipt = ue.receive_ballot(c_trans)
    print_step(f"UE accetta la scheda (ricevuta: {len(receipt)} bytes)")

    # MitM reinvia la stessa scheda
    print_attack("MitM reinvia c_trans intercettata")
    receipt2 = ue.receive_ballot(c_trans)

    if receipt2 is None:
        print_ok("UE ha rigettato la scheda replicata — nonce già visto nel registro")
    else:
        print_fail("UE ha accettato la scheda replicata!")


# =============================================================================
# ATTACCO 2 — TOKEN AUTO-GENERATO
# =============================================================================

def attacco_token_falso():
    print_header("ATTACCO 2 — Token Auto-Generato")
    print("  Scenario: un attaccante non abilitato costruisce un token")
    print("  firmandolo con una chiave propria invece di sk_AE.")
    separatore()

    ca, sa, ae, ue, voter, cert_E, pk_ue = setup_sistema()

    # Attaccante genera chiave propria e firma il token
    print_attack("Attaccante genera token con sk_fake (non sk_AE)")
    sk_fake, _ = generate_keys(2048)
    fake_token_id = os.urandom(32)
    fake_sigma = sign(sk_fake, fake_token_id)

    # Costruisce payload scheda con token falso
    nonce = os.urandom(32)
    cv = encrypt_OAEP(ae.k_pub_cifr, "Mario Rossi".encode())
    ballot_id = hash_SHA256(fake_token_id + cv + nonce)

    payload = (
        len(fake_token_id).to_bytes(2, "big") + fake_token_id
        + len(cv).to_bytes(4, "big") + cv
        + len(fake_sigma).to_bytes(4, "big") + fake_sigma
        + nonce
    )
    c_trans = encrypt_chunked(pk_ue, payload)

    print_step("Attaccante invia scheda con token falso all'UE")
    receipt = ue.receive_ballot(c_trans)

    if receipt is None:
        print_ok("UE ha rigettato la scheda — Vrfy_pkAE(token, sigma) = 0")
    else:
        print_fail("UE ha accettato la scheda con token falso!")


# =============================================================================
# ATTACCO 3 — CERTIFICATO CONTRAFFATTO (MitM)
# =============================================================================

def attacco_certificato_contraffatto():
    print_header("ATTACCO 3 — Certificato Contraffatto (MitM)")
    print("  Scenario: il MitM intercetta la comunicazione e presenta")
    print("  un certificato del SA contenente la propria chiave pubblica.")
    separatore()

    ca, sa, ae, ue, voter, cert_E, pk_ue = setup_sistema()

    # MitM genera propria coppia di chiavi
    print_attack("MitM sostituisce il certificato del SA con il proprio")
    sk_mitm, pk_mitm = generate_keys(2048)

    # Crea certificato contraffatto (non firmato dalla CA)
    fake_cert = {
        "entity_id": "SA",
        "public_key": pk_mitm,
        "signature": os.urandom(256)  # firma casuale non valida
    }
    print_step("MitM presenta cert_SA con pk_MitM al posto di pk_SA")

    # Elettore verifica il certificato tramite pkCA
    is_valid = ca.verify_certificate(fake_cert)

    if not is_valid:
        print_ok("Elettore ha rilevato il certificato contraffatto — firma CA invalida")
    else:
        print_fail("Elettore ha accettato il certificato contraffatto!")

    # Attacco B: MitM modifica il certificato autentico
    print_attack("MitM modifica pk_SA nel certificato autentico")
    cert_sa_reale = ca.get_certificate("SA")
    cert_modificato = {
        "entity_id": cert_sa_reale["entity_id"],
        "public_key": pk_mitm,           # sostituisce pk_SA con pk_MitM
        "signature": cert_sa_reale["signature"]  # firma originale ora invalida
    }
    is_valid2 = ca.verify_certificate(cert_modificato)

    if not is_valid2:
        print_ok("Elettore ha rilevato la modifica — firma CA copre anche pk_SA")
    else:
        print_fail("Elettore ha accettato il certificato modificato!")


# =============================================================================
# ATTACCO 4 — DOPPIA ABILITAZIONE (AE DISONESTA)
# =============================================================================

def attacco_doppia_abilitazione():
    print_header("ATTACCO 4 — Doppia Abilitazione (AE Disonesta)")
    print("  Scenario: AE disonesta emette due token validi per lo stesso")
    print("  elettore, consentendogli di votare due volte.")
    separatore()

    ca, sa, ae, ue, voter, cert_E, pk_ue = setup_sistema()

    # Primo voto regolare
    c_trans1 = voter.prepare_ballot("Mario Rossi", pk_ue)
    receipt1 = ue.receive_ballot(c_trans1)
    print_step("Primo voto registrato regolarmente")

    # AE disonesta: rimuove alice dal registro abilitati e rilascia secondo token
    print_attack("AE disonesta rimuove alice da _enabled_voters e rilascia secondo token")
    ae._enabled_voters["alice"] = True  # AE disonesta re-abilita alice
    et2 = ae.release_token("alice", voter.pk)
    ek2 = ae.release_encryption_key(voter.pk)
    resp2 = len(et2).to_bytes(4,"big") + et2 + len(ek2).to_bytes(4,"big") + ek2

    # Elettore riceve il secondo token
    pk_ae = ca.extract_public_key(ca.get_certificate("AE"))
    voter.receive_ae_response(resp2, pk_ae)
    print_step("AE rilascia secondo token — alice ora ha due token distinti")

    # Secondo voto con nuovo token
    c_trans2 = voter.prepare_ballot("Laura Bianchi", pk_ue)
    receipt2 = ue.receive_ballot(c_trans2)

    if receipt2 is not None:
        print_fail(
            "UE ha accettato il secondo voto — due token diversi appaiono legittimi. "
            "L'UE non può sapere che appartengono allo stesso elettore (limite dichiarato)"
        )
        print_step(f"Schede registrate: {ue.get_num_valid_ballots()} (atteso: 1)")

        # Mitigazione parziale: la discrepanza è rilevabile dalla verifica universale
        print_step(
            "Mitigazione parziale: al termine, |token_ids| > |L| è rilevabile "
            "confrontando i token pubblicati con la cardinalità di L firmata dal D"
        )
    else:
        print_ok("UE ha rigettato il secondo voto")


# =============================================================================
# ATTACCO 5 — MODIFICA SCHEDA IN TRANSITO (MitM)
# =============================================================================

def attacco_modifica_scheda():
    print_header("ATTACCO 5 — Modifica Scheda in Transito (MitM)")
    print("  Scenario: il MitM intercetta c_trans e altera un byte")
    print("  prima che raggiunga l'UE.")
    separatore()

    ca, sa, ae, ue, voter, cert_E, pk_ue = setup_sistema()

    c_trans = voter.prepare_ballot("Mario Rossi", pk_ue)
    print_step(f"Scheda originale prodotta ({len(c_trans)} bytes)")

    # MitM altera un byte nel mezzo del ciphertext
    print_attack("MitM altera un byte nel ciphertext c_trans")
    pos = len(c_trans) // 2
    c_tampered = c_trans[:pos] + bytes([c_trans[pos] ^ 0xFF]) + c_trans[pos+1:]
    print_step(f"Byte {pos} modificato: {c_trans[pos]:02x} → {c_tampered[pos]:02x}")

    receipt = ue.receive_ballot(c_tampered)

    if receipt is None:
        print_ok("UE ha scartato la scheda — padding OAEP non integro dopo l'alterazione")
    else:
        print_fail("UE ha accettato la scheda alterata!")


# =============================================================================
# ATTACCO 6 — COLLUSIONE AE + UE
# =============================================================================

def attacco_collusione_ae_ue():
    print_header("ATTACCO 6 — Collusione AE + UE (Pseudoanonimato)")
    print("  Scenario: AE e UE colludono condividendo le rispettive")
    print("  conoscenze per associare identità e preferenza.")
    separatore()

    ca, sa, ae, ue, voter, cert_E, pk_ue = setup_sistema()

    # Elettore vota
    c_trans = voter.prepare_ballot("Mario Rossi", pk_ue)
    ue.receive_ballot(c_trans)

    print_attack("AE condivide la mappatura (E_id → token_id) con UE")

    # AE conosce: E_id → token_id
    # Ricaviamo il token_id dal registro interno dell'AE
    # In un sistema reale l'AE avrebbe memorizzato questa associazione
    token_id = voter.token_id()
    print_step(f"AE rivela: 'alice' → token_id={token_id.hex()[:16]}...")

    # UE conosce: token_id → cv (voto cifrato)
    record = ue._registry.get(token_id)
    if record:
        print_step(f"UE ha in registro: token_id → cv={record['cv'].hex()[:16]}...")
        print_step("Ricostruzione catena: alice → token_id → cv")
        print_fail(
            "Pseudoanonimato violato — la collusione AE+UE permette di "
            "associare l'identità al voto cifrato. Limite dichiarato nel WP3: "
            "non eliminabile senza blind signature o ZKP."
        )
    else:
        print_step("token_id non trovato nel registro UE")


# =============================================================================
# ATTACCO 7 — UE DISONESTA (SCHEDE MULTIPLE PER STESSO TOKEN)
# =============================================================================

def attacco_ue_disonesta():
    print_header("ATTACCO 7 — UE Disonesta (Schede Multiple per Stesso Token)")
    print("  Scenario: UE disonesta non sovrascrive il record ma duplica")
    print("  la foglia nel Merkle Tree per conteggiare due volte lo stesso voto.")
    separatore()

    ca, sa, ae, ue, voter, cert_E, pk_ue = setup_sistema()

    # Voto legittimo
    c_trans = voter.prepare_ballot("Mario Rossi", pk_ue)
    ue.receive_ballot(c_trans)
    print_step("Scheda registrata regolarmente")

    # UE disonesta: duplica il record nel registro
    print_attack("UE disonesta duplica il record nel proprio registro")
    token_id = voter.token_id()
    record = ue._registry[token_id].copy()

    # Inserisce il record con un token_id fittizio per simulare duplicazione
    fake_token = os.urandom(32)
    ue._registry[fake_token] = record
    print_step(f"Registro UE ora contiene {len(ue._registry)} schede (atteso: 1)")

    # Scrutinio
    sk_ue_priv = ue.sk_ue
    encrypted_kpriv = ae.send_private_key(ue.pk_ue)
    verbale_pkg = ue.close_and_tally(encrypted_kpriv)

    vlen = int.from_bytes(verbale_pkg[:4], "big")
    verbale = json.loads(verbale_pkg[4:4+vlen])

    print_step(f"Verbale pubblicato: {verbale['num_schede']} schede, token_ids: {len(verbale['token_ids'])}")

    # Verifica universale: confronto token_ids con elettorato atteso
    elettorato_atteso = 1  # solo alice
    token_pubblicati = len(verbale["token_ids"])

    if token_pubblicati > elettorato_atteso:
        print_fail(
            f"Anomalia rilevabile: {token_pubblicati} token pubblicati > "
            f"{elettorato_atteso} elettori abilitati. "
            "Chiunque può rilevare la discrepanza confrontando |token_ids| con |L|."
        )
    else:
        print_ok("Nessuna anomalia rilevata")


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("\n" + "="*62)
    print("  SIMULAZIONE ATTACCHI — PROTOCOLLO VOTO ELETTRONICO")
    print("="*62)
    print("  Legenda:  ✓ MITIGATO  |  ✗ LIMITE DICHIARATO")

    attacco_replay()
    attacco_token_falso()
    attacco_certificato_contraffatto()
    attacco_doppia_abilitazione()
    attacco_modifica_scheda()
    attacco_collusione_ae_ue()
    attacco_ue_disonesta()

    print("\n" + "="*62)
    print("  SIMULAZIONE ATTACCHI COMPLETATA")
    print("="*62 + "\n")


if __name__ == "__main__":
    main()