"""
main.py
-------
Simulazione completa del protocollo di voto elettronico di Fantasy Company.

Esegue tutte le fasi del protocollo in sequenza:
    - Setup: inizializzazione CA, attori istituzionali, elettori
    - Fase 0: configurazione elezione (Direttore → AE)
    - Fase 1: autenticazione elettori (E → SA)
    - Fase 2: abilitazione e rilascio token (E → AE)
    - Fase 3: preparazione scheda (lato elettore)
    - Fase 4: trasmissione e registrazione (E → UE)
    - Fase 5: scrutinio e pubblicazione (AE → UE)
    - Fase 6: verifica individuale e universale

Uso:
    python main.py
"""

import json
import time

from Utils.crypto import generate_keys, verify
from Actors.CertificationAuthority import CertificationAuthority as CA
from Actors.AuthenticationSystem import AuthenticationSystem as SA
from Actors.ElectionAuthority import ElectionAuthority as AE
from Actors.Director import Director
from Actors.Voter import Voter
from Actors.ElectronicBallotBox import ElectronicBallotBox as UE


# =============================================================================
# UTILITÀ
# =============================================================================

def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_step(step, desc):
    print(f"  [{step}] {desc}")

def print_ok(msg):
    print(f"      ✓ {msg}")

def print_fail(msg):
    print(f"      ✗ {msg}")


# =============================================================================
# SETUP
# =============================================================================

def setup():
    print_header("SETUP — Inizializzazione sistema")

    # CA aziendale
    print_step("CA", "Generazione chiavi CA...")
    ca = CA()
    print_ok("CA inizializzata")

    # Sistema di Autenticazione
    print_step("SA", "Generazione chiavi SA e registrazione PKI...")
    sa = SA(ca)
    print_ok("SA inizializzato e certificato pubblicato nella PKI")

    # Autorità Elettorale
    print_step("AE", "Generazione chiavi AE e registrazione PKI...")
    ae = AE(ca)
    print_ok("AE inizializzata e certificato pubblicato nella PKI")

    # Direttore
    print_step("D", "Generazione chiavi Direttore e registrazione PKI...")
    sk_dir, pk_dir = generate_keys(2048)
    cert_dir = ca.generate_certificate("Direttore", pk_dir)
    ca.publish_certificate("Direttore", cert_dir)
    director = Director(sk_dir, pk_dir)
    print_ok("Direttore inizializzato e certificato pubblicato nella PKI")

    # Elettori
    print_step("E", "Generazione chiavi elettori...")
    voters = []
    voter_data = [
        ("alice", "Alice Rossi"),
        ("bob",   "Bob Bianchi"),
        ("carol", "Carol Verdi"),
    ]
    for voter_id, name in voter_data:
        sk, pk = generate_keys(2048)
        sk_fido, pk_fido = generate_keys(2048)
        cert_E = ca.generate_certificate(voter_id, pk)
        voter = Voter(voter_id, sk, pk, sk_fido, pk_fido)
        voters.append((voter, cert_E))
        print_ok(f"Elettore '{name}' ({voter_id}) inizializzato")

    # Urna Elettronica — sarà inizializzata dopo la Fase 0
    print_step("UE", "L'UE sarà inizializzata dopo la Fase 0")

    return ca, sa, ae, director, cert_dir, voters


# REGISTRAZIONE FIDO2 (prerequisito Fase 1)

def registrazione_fido2(sa, voters):
    print_header("REGISTRAZIONE FIDO2 — prerequisito Fase 1")

    for voter, _ in voters:
        # SA genera challenge di registrazione
        challenge_reg = sa.generate_registration_challenge(voter.voter_id)

        # Elettore firma la challenge con sk_FIDO
        sigma_reg = voter.respond_to_challenge(challenge_reg)

        # SA completa la registrazione
        ok = sa.complete_registration(voter.voter_id, voter.pk_fido, sigma_reg)
        if ok:
            print_ok(f"Elettore '{voter.voter_id}' registrato presso SA")
        else:
            print_fail(f"Registrazione fallita per '{voter.voter_id}'")


# =============================================================================
# FASE 0 — CONFIGURAZIONE ELEZIONE
# =============================================================================

def fase0(director, ae, ca, voters):
    print_header("FASE 0 — Configurazione elezione")

    candidates = ["Mario Rossi", "Laura Bianchi", "Giovanni Verdi"]
    offices = ["Roma", "Milano"]

    # Direttore recupera cert AE dalla PKI e configura l'elezione
    print_step("D→AE", "Direttore prepara e invia parametri elettorali...")
    cert_ae = ca.get_certificate("AE")
    pk_ae = ca.extract_public_key(cert_ae)
    encrypted_payload = director.configure_election(
        pk_ae=pk_ae,
        candidates=candidates,
        authorized_offices=offices,
        t_open=time.time(),
        duration_seconds=3600,
    )
    print_ok(f"Parametri cifrati e firmati ({len(encrypted_payload)} bytes)")

    # AE riceve e verifica i parametri
    print_step("AE", "AE decifra e verifica parametri...")
    cert_dir = ca.get_certificate("Direttore")
    ae.receive_params(encrypted_payload, cert_dir)
    print_ok("Parametri verificati e sessione inizializzata")
    print_ok(f"Candidati: {candidates}")

    # Aggiunge manualmente gli elettori all'elettorato 
    # (simulazione aggiunta votanti che verrebbe fatta tramite DB in receive_params)
    for voter, _ in voters:
        ae.add_voter(voter.voter_id)
    print_ok(f"Elettorato L = {[v.voter_id for v, _ in voters]}")

    # Inizializza ElectronicBallotBox con chiavi proprie e parametri dell'elezione
    print_step("UE", "Inizializzazione Urna Elettronica...")
    sk_ue, pk_ue = generate_keys(2048)
    cert_ue = ae._ca.generate_certificate("UE", pk_ue)
    ae._ca.publish_certificate("UE", cert_ue)
    ue = UE(
        sk_ue=sk_ue,
        pk_ue=pk_ue,
        pk_ae=ae.public_key,
        candidates=candidates,
    )
    print_ok("UE inizializzata e certificato pubblicato nella PKI")

    return ue, candidates


# =============================================================================
# FASE 1 — AUTENTICAZIONE ELETTORE
# =============================================================================

def fase1(sa, ca, voter, cert_E):
    print_header(f"FASE 1 — Autenticazione elettore '{voter.voter_id}'")

    # SA recupera cert E (non dalla PKI — scambio diretto)
    # E recupera cert SA dalla PKI
    cert_sa = ca.get_certificate("SA")
    pk_sa = ca.extract_public_key(cert_sa)
    print_step("E→SA", f"Elettore '{voter.voter_id}' richiede autenticazione...")

    # SA genera challenge
    challenge = sa.generate_auth_challenge(voter.voter_id)
    print_ok(f"Challenge generata ({len(challenge)} bytes)")

    # Elettore firma la challenge con sk_FIDO
    sigma_auth = voter.respond_to_challenge(challenge)
    print_ok("Challenge firmata con sk_FIDO")

    # SA verifica autenticazione
    ok = sa.verify_authentication(voter.voter_id, sigma_auth, cert_E)
    if not ok:
        print_fail("Autenticazione fallita")
        return None, None
    print_ok("Autenticazione FIDO2 verificata")

    # SA rilascia auth_proof cifrata con pk_E
    auth_proof_encrypted = sa.release_auth_proof(voter.voter_id, challenge, voter.pk)
    print_ok(f"auth_proof cifrata rilasciata ({len(auth_proof_encrypted)} bytes)")

    # Elettore decifra auth_proof
    ok = voter.receive_auth_proof(auth_proof_encrypted)
    if not ok:
        print_fail("Decifratura auth_proof fallita")
        return None, None
    print_ok("auth_proof decifrata e conservata")

    return challenge, pk_sa


# =============================================================================
# FASE 2 — ABILITAZIONE E RILASCIO TOKEN
# =============================================================================

def fase2(ae, ca, voter, cert_E):
    print_header(f"FASE 2 — Abilitazione elettore '{voter.voter_id}'")

    # AE recupera cert SA dalla PKI per verificare auth_proof
    cert_sa = ca.get_certificate("SA")
    pk_sa = ca.extract_public_key(cert_sa)

    # Elettore cifra auth_proof con pk_AE e invia ad AE
    cert_ae = ca.get_certificate("AE")
    pk_ae = ca.extract_public_key(cert_ae)
    print_step("E→AE", "Elettore invia richiesta di abilitazione...")
    encrypted_request = voter.prepare_authorization_request(pk_ae)
    print_ok(f"Richiesta cifrata ({len(encrypted_request)} bytes)")

    # AE verifica e abilita l'elettore
    print_step("AE", "AE verifica richiesta...")
    entity_id = ae.receive_enablement_request(encrypted_request, cert_E, pk_sa)
    print_ok(f"Elettore '{entity_id}' abilitato")

    # AE rilascia token cifrato con pk_E
    print_step("AE→E", "AE rilascia token...")
    encrypted_token = ae.release_token(entity_id, voter.pk)
    print_ok(f"Token cifrato rilasciato ({len(encrypted_token)} bytes)")

    # AE rilascia K_pub_cifr cifrata con pk_E
    print_step("AE→E", "AE rilascia K_pub_cifr...")
    encrypted_kpub = ae.release_encryption_key(voter.pk)
    print_ok(f"K_pub_cifr cifrata rilasciata ({len(encrypted_kpub)} bytes)")

    # Costruisce il pacchetto AE→E nel formato atteso dall'elettore:
    # 4B len(token) | token | 4B len(kpub) | kpub
    ae_response = (
        len(encrypted_token).to_bytes(4, "big") + encrypted_token +
        len(encrypted_kpub).to_bytes(4, "big") + encrypted_kpub
    )

    # Elettore elabora la risposta dell'AE
    ok = voter.receive_ae_response(ae_response, pk_ae)
    if not ok:
        print_fail("Elaborazione risposta AE fallita")
        return False
    print_ok("Token e K_pub_cifr verificati e conservati")
    return True


# =============================================================================
# FASI 3 e 4 — PREPARAZIONE E TRASMISSIONE SCHEDA
# =============================================================================

def fase3_4(ue, ca, voter, preference):
    print_header(f"FASI 3-4 — Voto di '{voter.voter_id}': '{preference}'")

    # Elettore recupera pk_UE dalla PKI
    cert_ue = ca.get_certificate("UE")
    pk_ue = ca.extract_public_key(cert_ue)

    # Fase 3 — preparazione scheda
    print_step("E", "Elettore prepara la scheda...")
    c_trans = voter.prepare_ballot(preference, pk_ue)
    print_ok(f"Scheda cifrata preparata ({len(c_trans)} bytes)")

    # Fase 4 — trasmissione all'UE
    print_step("E→UE", "Elettore trasmette scheda all'UE...")
    receipt = ue.receive_ballot(c_trans)
    if receipt is None:
        print_fail("UE ha rifiutato la scheda")
        return False
    print_ok(f"Ricevuta firmata rilasciata ({len(receipt)} bytes)")

    # Elettore verifica la ricevuta
    ok = voter.validate_receipt(receipt, pk_ue)
    if not ok:
        print_fail("Verifica ricevuta fallita")
        return False
    print_ok("Ricevuta verificata e conservata")
    return True


# =============================================================================
# FASE 5 — SCRUTINIO E PUBBLICAZIONE
# =============================================================================

def fase5(ae, ue, ca):
    print_header("FASE 5 — Scrutinio e pubblicazione")

    # AE recupera pk_UE dalla PKI e trasmette K_priv_cifr
    print_step("AE→UE", "AE trasmette K_priv_cifr all'UE...")
    cert_ue = ca.get_certificate("UE")
    pk_ue = ca.extract_public_key(cert_ue)
    encrypted_kpriv = ae.send_private_key(pk_ue)
    print_ok(f"K_priv_cifr cifrata trasmessa ({len(encrypted_kpriv)} bytes)")

    # UE esegue lo scrutinio
    print_step("UE", "UE decifra schede e calcola risultato...")
    verbale_package = ue.close_and_tally(encrypted_kpriv)
    print_ok(f"Scrutinio completato ({len(verbale_package)} bytes)")

    # Parsing verbale
    verbale_len = int.from_bytes(verbale_package[:4], "big")
    verbale_json = verbale_package[4:4 + verbale_len]
    sigma_verbale = verbale_package[4 + verbale_len:]
    verbale = json.loads(verbale_json)

    print_ok("Risultato pubblicato nel registro pubblico elettorale:")
    for candidato, voti in verbale["risultato"].items():
        if candidato == "__scheda_bianca__":
            print(f"        Schede bianche: {voti}")
        elif candidato == "__scheda_nulla__":
            print(f"        Schede nulle: {voti}")
        else:
            print(f"        {candidato}: {voti} voti")
    print_ok(f"Totale schede valide: {verbale['num_schede']}")

    return verbale, sigma_verbale


# =============================================================================
# FASE 6 — VERIFICA INDIVIDUALE E UNIVERSALE
# =============================================================================

def fase6_individuale(ue, ca, voter):
    print_header(f"FASE 6 — Verifica individuale '{voter.voter_id}'")

    if voter.token_id() is None:
        print_fail("Token non disponibile")
        return False

    # Recupera Merkle Proof dall'UE
    print_step("E→UE", "Elettore richiede Merkle Proof...")
    result = ue.get_merkle_proof(voter.token_id())
    if result is None:
        print_fail("Merkle Proof non disponibile")
        return False

    proof, root, sigma_root = result
    print_ok(f"Merkle Proof ricevuta ({len(proof)} nodi)")

    # Verifica inclusione
    cert_ue = ca.get_certificate("UE")
    pk_ue = ca.extract_public_key(cert_ue)
    ok = voter.verify_inclusion(proof, root, sigma_root, pk_ue)
    if ok:
        print_ok("Verifica individuale SUPERATA — scheda inclusa nel conteggio")
    else:
        print_fail("Verifica individuale FALLITA")
    return ok


def fase6_universale(ue, ca, verbale, sigma_verbale):
    print_header("FASE 6 — Verifica universale")

    cert_ue = ca.get_certificate("UE")
    pk_ue = ca.extract_public_key(cert_ue)

    # 1. Verifica firma sul verbale
    print_step("1", "Verifica firma digitale sul verbale...")
    verbale_json = json.dumps(verbale, sort_keys=True, ensure_ascii=True).encode()
    ok = verify(pk_ue, sigma_verbale, verbale_json)
    if ok:
        print_ok("Firma verbale verificata")
    else:
        print_fail("Firma verbale NON valida")
        return False

    # 2. Verifica coerenza numerica
    print_step("2", "Verifica coerenza numerica...")
    total_voti = sum(verbale["risultato"].values())
    num_schede = verbale["num_schede"]
    if total_voti == num_schede:
        print_ok(f"Coerenza verificata: {total_voti} voti = {num_schede} schede")
    else:
        print_fail(f"Incoerenza: {total_voti} voti ≠ {num_schede} schede")
        return False

    # 3. Verifica token univoci
    print_step("3", "Verifica assenza token duplicati...")
    token_ids = verbale["token_ids"]
    if len(token_ids) == len(set(token_ids)):
        print_ok(f"Nessun token duplicato ({len(token_ids)} token univoci)")
    else:
        print_fail("Token duplicati rilevati!")
        return False

    print_ok("Verifica universale SUPERATA")
    return True


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("\n" + "="*60)
    print("  SIMULAZIONE PROTOCOLLO VOTO ELETTRONICO")
    print("="*60)

    try:
        # Setup
        ca, sa, ae, director, cert_dir, voters = setup()

        # Registrazione FIDO2
        registrazione_fido2(sa, voters)

        # Fase 0
        ue, candidates = fase0(director, ae, ca, voters)

        # Preferenze degli elettori
        preferenze = {
            "alice": "Mario Rossi",
            "bob":   "Laura Bianchi",
            "carol": "Mario Rossi",
        }

        # Fasi 1, 2, 3, 4 per ogni elettore
        for voter, cert_E in voters:
            # Fase 1
            challenge, pk_sa = fase1(sa, ca, voter, cert_E)
            if challenge is None:
                continue

            # Fase 2
            ok = fase2(ae, ca, voter, cert_E)
            if not ok:
                continue

            # Fasi 3-4
            preference = preferenze[voter.voter_id]
            ok = fase3_4(ue, ca, voter, preference)
            if not ok:
                continue

        # Fase 5
        verbale, sigma_verbale = fase5(ae, ue, ca)

        # Fase 6 — verifica individuale per ogni elettore
        for voter, _ in voters:
            fase6_individuale(ue, ca, voter)

        # Fase 6 — verifica universale
        fase6_universale(ue, ca, verbale, sigma_verbale)

        print("\n" + "="*60)
        print("  SIMULAZIONE COMPLETATA CON SUCCESSO")
        print("="*60 + "\n")

    except Exception as e:
        print(f"\n  ERRORE: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()