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
# SELEZIONE INTERATTIVA PREFERENZA
# =============================================================================

def seleziona_preferenza(voter_id, candidates):
    """
    Mostra la lista dei candidati e chiede all'utente di selezionare
    una preferenza da riga di comando.

    :param voter_id: identificativo dell'elettore
    :param candidates: lista dei candidati disponibili
    :returns: preferenza selezionata (stringa) o "" per scheda bianca
    """
    print(f"\n  ┌{'─'*50}┐")
    print(f"  │  Cabina elettorale — Elettore: {voter_id:<18}│")
    print(f"  ├{'─'*50}┤")
    for i, candidate in enumerate(candidates, 1):
        print(f"  │  {i}. {candidate:<46}│")
    print(f"  │  0. Scheda bianca{'':32}│")
    print(f"  └{'─'*50}┘")

    while True:
        try:
            scelta = input(f"\n  Inserisci il numero della tua scelta: ").strip()
            numero = int(scelta)
            if numero == 0:
                print(f"\n  Hai scelto: SCHEDA BIANCA")
                conferma = input("  Confermi? (s/n): ").strip().lower()
                if conferma == 's':
                    return ""
                else:
                    print("  Scelta annullata. Riprova.")
            elif 1 <= numero <= len(candidates):
                candidato = candidates[numero - 1]
                print(f"\n  Hai scelto: {candidato}")
                conferma = input("  Confermi? (s/n): ").strip().lower()
                if conferma == 's':
                    return candidato
                else:
                    print("  Scelta annullata. Riprova.")
            else:
                print(f"  Scelta non valida. Inserisci un numero tra 0 e {len(candidates)}.")
        except ValueError:
            print("  Input non valido. Inserisci un numero.")


# =============================================================================
# SETUP
# =============================================================================

def setup():
    print_header("SETUP — Inizializzazione sistema")

    print_step("CA", "Generazione chiavi CA...")
    ca = CA()
    print_ok("CA inizializzata")

    print_step("SA", "Generazione chiavi SA e registrazione PKI...")
    sa = SA(ca)
    print_ok("SA inizializzato e certificato pubblicato nella PKI")

    print_step("AE", "Generazione chiavi AE e registrazione PKI...")
    ae = AE(ca)
    print_ok("AE inizializzata e certificato pubblicato nella PKI")

    print_step("D", "Generazione chiavi Direttore e registrazione PKI...")
    sk_dir, pk_dir = generate_keys(2048)
    cert_dir = ca.generate_certificate("Direttore", pk_dir)
    ca.publish_certificate("Direttore", cert_dir)
    director = Director(sk_dir, pk_dir)
    print_ok("Direttore inizializzato e certificato pubblicato nella PKI")

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

    print_step("UE", "L'UE sarà inizializzata dopo la Fase 0")

    return ca, sa, ae, director, cert_dir, voters


# =============================================================================
# REGISTRAZIONE FIDO2
# =============================================================================

def registrazione_fido2(sa, voters):
    print_header("REGISTRAZIONE FIDO2 — prerequisito Fase 1")

    for voter, cert_E in voters:
        challenge_reg = sa.generate_registration_challenge(voter.voter_id)
        sigma_reg = voter.respond_to_challenge(challenge_reg)
        ok = sa.complete_registration(voter.voter_id, voter.pk_fido, sigma_reg)
        if ok:
            print_ok(f"Elettore '{voter.voter_id}' registrato presso SA")
        else:
            print_fail(f"Registrazione fallita per '{voter.voter_id}'")


# =============================================================================
# FASE 0
# =============================================================================

def fase0(director, ae, ca, voters):
    print_header("FASE 0 — Configurazione elezione")

    candidates = ["Mario Rossi", "Laura Bianchi", "Giovanni Verdi"]
    offices = ["Roma", "Milano"]

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

    print_step("AE", "AE decifra e verifica parametri...")
    cert_dir = ca.get_certificate("Direttore")
    ae.receive_params(encrypted_payload, cert_dir)
    print_ok("Parametri verificati e sessione inizializzata")
    print_ok(f"Candidati: {candidates}")

    for voter, _ in voters:
        ae.add_voter(voter.voter_id)
    print_ok(f"Elettorato L = {[v.voter_id for v, _ in voters]}")

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
# FASE 1
# =============================================================================

def fase1(sa, ca, voter, cert_E):
    print_header(f"FASE 1 — Autenticazione elettore '{voter.voter_id}'")

    cert_sa = ca.get_certificate("SA")
    pk_sa = ca.extract_public_key(cert_sa)
    print_step("E→SA", f"Elettore '{voter.voter_id}' richiede autenticazione...")

    challenge = sa.generate_auth_challenge(voter.voter_id)
    print_ok(f"Challenge generata ({len(challenge)} bytes)")

    sigma_auth = voter.respond_to_challenge(challenge)
    print_ok("Challenge firmata con sk_FIDO")

    ok = sa.verify_authentication(voter.voter_id, sigma_auth, cert_E)
    if not ok:
        print_fail("Autenticazione fallita")
        return None, None
    print_ok("Autenticazione FIDO2 verificata")

    auth_proof_encrypted = sa.release_auth_proof(voter.voter_id, challenge, voter.pk)
    print_ok(f"auth_proof cifrata rilasciata ({len(auth_proof_encrypted)} bytes)")

    ok = voter.receive_auth_proof(auth_proof_encrypted)
    if not ok:
        print_fail("Decifratura auth_proof fallita")
        return None, None
    print_ok("auth_proof decifrata e conservata")

    return challenge, pk_sa


# =============================================================================
# FASE 2
# =============================================================================

def fase2(ae, ca, voter, cert_E):
    print_header(f"FASE 2 — Abilitazione elettore '{voter.voter_id}'")

    cert_sa = ca.get_certificate("SA")
    pk_sa = ca.extract_public_key(cert_sa)

    cert_ae = ca.get_certificate("AE")
    pk_ae = ca.extract_public_key(cert_ae)
    print_step("E→AE", "Elettore invia richiesta di abilitazione...")
    encrypted_request = voter.prepare_authorization_request(pk_ae)
    print_ok(f"Richiesta cifrata ({len(encrypted_request)} bytes)")

    print_step("AE", "AE verifica richiesta...")
    entity_id = ae.receive_enablement_request(encrypted_request, cert_E, pk_sa)
    print_ok(f"Elettore '{entity_id}' abilitato")

    print_step("AE→E", "AE rilascia token...")
    encrypted_token = ae.release_token(entity_id, voter.pk)
    print_ok(f"Token cifrato rilasciato ({len(encrypted_token)} bytes)")

    print_step("AE→E", "AE rilascia K_pub_cifr...")
    encrypted_kpub = ae.release_encryption_key(voter.pk)
    print_ok(f"K_pub_cifr cifrata rilasciata ({len(encrypted_kpub)} bytes)")

    ae_response = (
        len(encrypted_token).to_bytes(4, "big") + encrypted_token +
        len(encrypted_kpub).to_bytes(4, "big") + encrypted_kpub
    )

    ok = voter.receive_ae_response(ae_response, pk_ae)
    if not ok:
        print_fail("Elaborazione risposta AE fallita")
        return False
    print_ok("Token e K_pub_cifr verificati e conservati")
    return True


# =============================================================================
# FASI 3 e 4
# =============================================================================

def fase3_4(ue, ca, voter, preference):
    label = preference if preference else "SCHEDA BIANCA"
    print_header(f"FASI 3-4 — Voto di '{voter.voter_id}': '{label}'")

    cert_ue = ca.get_certificate("UE")
    pk_ue = ca.extract_public_key(cert_ue)

    print_step("E", "Elettore prepara la scheda...")
    c_trans = voter.prepare_ballot(preference, pk_ue)
    print_ok(f"Scheda cifrata preparata ({len(c_trans)} bytes)")

    print_step("E→UE", "Elettore trasmette scheda all'UE...")
    receipt = ue.receive_ballot(c_trans)
    if receipt is None:
        print_fail("UE ha rifiutato la scheda")
        return False
    print_ok(f"Ricevuta firmata rilasciata ({len(receipt)} bytes)")

    ok = voter.validate_receipt(receipt, pk_ue)
    if not ok:
        print_fail("Verifica ricevuta fallita")
        return False
    print_ok("Ricevuta verificata e conservata")
    return True


# =============================================================================
# FASE 5
# =============================================================================

def fase5(ae, ue, ca):
    print_header("FASE 5 — Scrutinio e pubblicazione")

    print_step("AE→UE", "AE trasmette K_priv_cifr all'UE...")
    cert_ue = ca.get_certificate("UE")
    pk_ue = ca.extract_public_key(cert_ue)
    encrypted_kpriv = ae.send_private_key(pk_ue)
    print_ok(f"K_priv_cifr cifrata trasmessa ({len(encrypted_kpriv)} bytes)")

    print_step("UE", "UE decifra schede e calcola risultato...")
    verbale_package = ue.close_and_tally(encrypted_kpriv)
    print_ok(f"Scrutinio completato ({len(verbale_package)} bytes)")

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
# FASE 6
# =============================================================================

def fase6_individuale(ue, ca, voter):
    print_header(f"FASE 6 — Verifica individuale '{voter.voter_id}'")

    if voter.token_id() is None:
        print_fail("Token non disponibile")
        return False

    print_step("E→UE", "Elettore richiede Merkle Proof...")
    result = ue.get_merkle_proof(voter.token_id())
    if result is None:
        print_fail("Merkle Proof non disponibile")
        return False

    proof, root, sigma_root = result
    print_ok(f"Merkle Proof ricevuta ({len(proof)} nodi)")

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

    print_step("1", "Verifica firma digitale sul verbale...")
    verbale_json = json.dumps(verbale, sort_keys=True, ensure_ascii=True).encode()
    ok = verify(pk_ue, sigma_verbale, verbale_json)
    if ok:
        print_ok("Firma verbale verificata")
    else:
        print_fail("Firma verbale NON valida")
        return False

    print_step("2", "Verifica coerenza numerica...")
    total_voti = sum(verbale["risultato"].values())
    num_schede = verbale["num_schede"]
    if total_voti == num_schede:
        print_ok(f"Coerenza verificata: {total_voti} voti = {num_schede} schede")
    else:
        print_fail(f"Incoerenza: {total_voti} voti ≠ {num_schede} schede")
        return False

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
# SELEZIONE INTERATTIVA PREFERENZA CON OPZIONE RIVOTO
# =============================================================================

def vuoi_rivotare(voter_id):
    """
    Chiede all'elettore se vuole modificare il proprio voto.
    
    :param voter_id: identificativo dell'elettore
    :returns: True se vuole rivotare, False altrimenti
    """
    print(f"\n  Elettore '{voter_id}' ha già espresso una preferenza.")
    scelta = input("  Vuoi modificare il tuo voto? (s/n): ").strip().lower()
    return scelta == 's'


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("\n" + "="*60)
    print("  SIMULAZIONE INTERATTIVA PROTOCOLLO VOTO ELETTRONICO")
    print("="*60)

    try:
        # Setup
        ca, sa, ae, director, cert_dir, voters = setup()

        # Registrazione FIDO2
        registrazione_fido2(sa, voters)

        # Fase 0
        ue, candidates = fase0(director, ae, ca, voters)

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

            # Primo voto
            preference = seleziona_preferenza(voter.voter_id, candidates)
            ok = fase3_4(ue, ca, voter, preference)
            if not ok:
                continue

            # Rivoto — l'elettore può modificare la preferenza
            while vuoi_rivotare(voter.voter_id):

                print_header(
                    f"RIVOTO — Elettore '{voter.voter_id}'"
                )
                print(f"  Il voto precedente ('{preference if preference else 'SCHEDA BIANCA'}') "
                    f"verrà sovrascritto.")

                # Fase 1 — ri-autenticazione presso SA
                challenge, pk_sa = fase1(sa, ca, voter, cert_E)
                if challenge is None:
                    print_fail("Ri-autenticazione fallita")
                    break

                # Nuova preferenza
                new_preference = seleziona_preferenza(
                    voter.voter_id, candidates
                )

                # Fasi 3-4 con stesso token — UE sovrascrive
                ok = fase3_4(ue, ca, voter, new_preference)
                if not ok:
                    print_fail("Invio nuovo voto fallito")
                    break

                print_ok(
                    f"Voto aggiornato: "
                    f"'{preference if preference else 'SCHEDA BIANCA'}' "
                    f"→ "
                    f"'{new_preference if new_preference else 'SCHEDA BIANCA'}'"
                )
                preference = new_preference

        # Fase 5
        verbale, sigma_verbale = fase5(ae, ue, ca)

        # Fase 6 — verifica individuale
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