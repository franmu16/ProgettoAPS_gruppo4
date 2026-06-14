"""ì
Misurazione delle prestazioni del protocollo di voto elettronico.

Misura:
    1. Costo computazionale delle primitive crittografiche
    2. Dimensione dei messaggi scambiati
    3. Latenza delle operazioni di verifica
    4. Tempi di interazione per fase
    5. Scalabilità al crescere del numero di elettori
"""

import time
import statistics
import os

from Utils.crypto import generate_keys, encrypt_OAEP, decrypt_OAEP, sign, verify, hash_SHA256, encrypt_chunked, decrypt_chunked
from Actors.CertificationAuthority import CertificationAuthority as CA
from Actors.AuthenticationSystem import AuthenticationSystem as SA
from Actors.ElectionAuthority import ElectionAuthority as AE
from Actors.Director import Director
from Actors.Voter import Voter
from Actors.ElectronicBallotBox import ElectronicBallotBox as UE
from Utils.MerkleTree import build_merkle_tree, generate_merkle_proof, verify_merkle_proof


# =============================================================================
# UTILITÀ
# =============================================================================

RIPETIZIONI = 10  # numero di ripetizioni per ogni misurazione

def misura_tempo(funzione, *args, ripetizioni=RIPETIZIONI):
    """
    Esegue una funzione N volte e restituisce:
    (media_ms, min_ms, max_ms)
    """
    tempi = []
    for _ in range(ripetizioni):
        start = time.perf_counter()
        funzione(*args)
        end = time.perf_counter()
        tempi.append((end - start) * 1000)  # in millisecondi
    return (
        statistics.mean(tempi),
        min(tempi),
        max(tempi)
    )

def print_header(title):
    print(f"\n{'='*65}")
    print(f"  {title}")
    print(f"{'='*65}")

def print_risultato(operazione, media, minimo, massimo, unita="ms"):
    print(f"  {operazione:<45} {media:>7.2f} {unita}  (min={minimo:.2f}, max={massimo:.2f})")

def print_dimensione(messaggio, dimensione):
    print(f"  {messaggio:<45} {dimensione:>7} bytes")

def separatore():
    print(f"  {'-'*63}")


# =============================================================================
# 1. PRIMITIVE CRITTOGRAFICHE
# =============================================================================

def benchmark_primitive():
    print_header("1. COSTO COMPUTAZIONALE PRIMITIVE CRITTOGRAFICHE")

    sk, pk = generate_keys(2048)
    messaggio = os.urandom(32)
    messaggio_grande = os.urandom(500)

    # Generazione chiavi
    print("\n  Generazione chiavi RSA:")
    separatore()
    for size in [2048, 4096]:
        media, mn, mx = misura_tempo(generate_keys, size, ripetizioni=5)
        print_risultato(f"  generate_keys({size} bit)", media, mn, mx)


    # Cifratura RSA-OAEP
    print("\n  Cifratura/Decifratura RSA-OAEP:")
    separatore()
    ct = encrypt_OAEP(pk, messaggio)
    media, mn, mx = misura_tempo(encrypt_OAEP, pk, messaggio)
    print_risultato("  encrypt_OAEP (32 bytes)", media, mn, mx)

    media, mn, mx = misura_tempo(decrypt_OAEP, sk, ct)
    print_risultato("  decrypt_OAEP (32 bytes)", media, mn, mx)


    # Chunking
    print("\n  Cifratura/Decifratura chunked (messaggi grandi):")
    separatore()
    ct_chunked = encrypt_chunked(pk, messaggio_grande)
    media, mn, mx = misura_tempo(encrypt_chunked, pk, messaggio_grande)
    print_risultato("  encrypt_chunked (500 bytes)", media, mn, mx)

    media, mn, mx = misura_tempo(decrypt_chunked, sk, ct_chunked)
    print_risultato("  decrypt_chunked (500 bytes)", media, mn, mx)

    # Firma RSA-PSS
    print("\n  Firma/Verifica RSA-PSS:")
    separatore()
    sigma = sign(sk, messaggio)
    media, mn, mx = misura_tempo(sign, sk, messaggio)
    print_risultato("  sign (32 bytes)", media, mn, mx)

    media, mn, mx = misura_tempo(verify, pk, sigma, messaggio)
    print_risultato("  verify (32 bytes)", media, mn, mx)

    # Hashing SHA-256
    print("\n  Hashing SHA-256:")
    separatore()
    for size in [32, 256, 1024]:
        msg = os.urandom(size)
        media, mn, mx = misura_tempo(hash_SHA256, msg)
        print_risultato(f"  hash_SHA256 ({size} bytes)", media, mn, mx)


# =============================================================================
# 2. DIMENSIONE DEI MESSAGGI
# =============================================================================

def benchmark_dimensioni():
    print_header("2. DIMENSIONE DEI MESSAGGI SCAMBIATI")

    # Setup
    ca = CA()
    sa = SA(ca)
    ae = AE(ca)
    sk_dir, pk_dir = generate_keys(2048)
    cert_dir = ca.generate_certificate("Direttore", pk_dir)
    ca.publish_certificate("Direttore", cert_dir)
    director = Director(sk_dir, pk_dir)

    sk_voter, pk_voter = generate_keys(2048)
    sk_fido, pk_fido = generate_keys(2048)
    voter = Voter("test", sk_voter, pk_voter, sk_fido, pk_fido)
    cert_E = ca.generate_certificate("test", pk_voter)

    sk_ue, pk_ue = generate_keys(2048)
    cert_ue = ca.generate_certificate("UE", pk_ue)
    ca.publish_certificate("UE", cert_ue)

    # Fase 0
    cert_ae = ca.get_certificate("AE")
    pk_ae_key = ca.extract_public_key(cert_ae)
    payload_f0 = director.configure_election(
        pk_ae=pk_ae_key,
        candidates=["Mario Rossi", "Laura Bianchi", "Giovanni Verdi"],
        authorized_offices=["Roma", "Milano"],
        t_open=time.time(),
        duration_seconds=3600,
    )
    ae.receive_params(payload_f0, cert_dir)
    ae.add_voter("test")

    ue = UE(
        sk_ue=sk_ue,
        pk_ue=pk_ue,
        pk_ae=ae.public_key,
        candidates=["Mario Rossi", "Laura Bianchi", "Giovanni Verdi"],
    )

    # Registrazione FIDO2
    ch_reg = sa.generate_registration_challenge("test")
    sig_reg = voter.respond_to_challenge(ch_reg)
    sa.complete_registration("test", pk_fido, sig_reg)

    # Fase 1
    challenge = sa.generate_auth_challenge("test")
    sigma_auth = voter.respond_to_challenge(challenge)
    sa.verify_authentication("test", sigma_auth, cert_E)
    auth_proof_enc = sa.release_auth_proof("test", challenge, pk_voter)

    # Fase 2
    voter.receive_auth_proof(auth_proof_enc)
    pk_ae_key2 = ca.extract_public_key(ca.get_certificate("AE"))
    enc_req = voter.prepare_authorization_request(pk_ae_key2)
    cert_sa = ca.get_certificate("SA")
    pk_sa = ca.extract_public_key(cert_sa)
    ae.receive_enablement_request(enc_req, cert_E, pk_sa)
    enc_token = ae.release_token("test", pk_voter)
    enc_kpub = ae.release_encryption_key(pk_voter)
    ae_response = (
        len(enc_token).to_bytes(4, "big") + enc_token +
        len(enc_kpub).to_bytes(4, "big") + enc_kpub
    )
    voter.receive_ae_response(ae_response, pk_ae_key2)

    # Fase 3-4
    c_trans = voter.prepare_ballot("Mario Rossi", pk_ue)
    receipt = ue.receive_ballot(c_trans)

    # Fase 5
    enc_kpriv = ae.send_private_key(pk_ue)
    verbale_pkg = ue.close_and_tally(enc_kpriv)

    # Certificati
    print("\n  Certificati:")
    separatore()
    print_dimensione("  Certificato attore istituzionale", len(str(cert_dir).encode()))

    print("\n  Fase 0 — Configurazione elezione:")
    separatore()
    print_dimensione("  D → AE: Enc(M || sigma_M)", len(payload_f0))

    print("\n  Fase 1 — Autenticazione:")
    separatore()
    print_dimensione("  SA → E: challenge (in chiaro)", len(challenge))
    print_dimensione("  E → SA: sigma_auth (in chiaro)", len(sigma_auth))
    print_dimensione("  SA → E: auth_proof cifrata", len(auth_proof_enc))

    print("\n  Fase 2 — Abilitazione:")
    separatore()
    print_dimensione("  E → AE: richiesta abilitazione cifrata", len(enc_req))
    print_dimensione("  AE → E: token cifrato", len(enc_token))
    print_dimensione("  AE → E: K_pub_cifr cifrata", len(enc_kpub))

    print("\n  Fasi 3-4 — Scheda:")
    separatore()
    print_dimensione("  E → UE: scheda cifrata (c_trans)", len(c_trans))
    print_dimensione("  UE → E: ricevuta firmata (in chiaro)", len(receipt))

    print("\n  Fase 5 — Scrutinio:")
    separatore()
    print_dimensione("  AE → UE: K_priv_cifr cifrata", len(enc_kpriv))
    vlen = int.from_bytes(verbale_pkg[:4], "big")
    print_dimensione("  UE → RPE: verbale JSON", vlen)
    print_dimensione("  UE → RPE: sigma_verbale", len(verbale_pkg) - 4 - vlen)
    print_dimensione("  UE → RPE: verbale completo", len(verbale_pkg))


# =============================================================================
# 3. LATENZA OPERAZIONI DI VERIFICA
# =============================================================================

def benchmark_verifiche():
    print_header("3. LATENZA OPERAZIONI DI VERIFICA")

    sk, pk = generate_keys(2048)
    messaggio = os.urandom(256)
    sigma = sign(sk, messaggio)

    print("\n  Verifica firma digitale:")
    separatore()
    media, mn, mx = misura_tempo(verify, pk, sigma, messaggio)
    print_risultato("  Vrfy_pk(m, sigma)", media, mn, mx)

    # Verifica certificato CA
    ca = CA()
    sk2, pk2 = generate_keys(2048)
    cert = ca.generate_certificate("test", pk2)

    media, mn, mx = misura_tempo(ca.verify_certificate, cert)
    print_risultato("  verify_certificate(cert)", media, mn, mx)

    # Merkle Proof
    print("\n  Verifica Merkle Proof:")
    separatore()
    for n in [10, 100, 1000, 10000]:
        leaves = [os.urandom(32) for _ in range(n)]
        root, tree = build_merkle_tree(leaves)
        proof = generate_merkle_proof(0, tree)
        media, mn, mx = misura_tempo(
            verify_merkle_proof, leaves[0], proof, root
        )
        print_risultato(f"  verify_merkle_proof (n={n:>5} foglie)", media, mn, mx)

    # Costruzione Merkle Tree
    print("\n  Costruzione Merkle Tree:")
    separatore()
    for n in [10, 100, 1000, 10000]:
        leaves = [os.urandom(32) for _ in range(n)]
        media, mn, mx = misura_tempo(build_merkle_tree, leaves, ripetizioni=5)
        print_risultato(f"  build_merkle_tree (n={n:>5} foglie)", media, mn, mx)


# =============================================================================
# 4. TEMPI DI INTERAZIONE PER FASE
# =============================================================================

def benchmark_fasi():
    print_header("4. TEMPI DI INTERAZIONE PER FASE")

    def esegui_protocollo_completo():
        ca = CA()
        sa = SA(ca)
        ae = AE(ca)
        sk_dir, pk_dir = generate_keys(2048)
        cert_dir = ca.generate_certificate("Direttore", pk_dir)
        ca.publish_certificate("Direttore", cert_dir)
        director = Director(sk_dir, pk_dir)

        sk_v, pk_v = generate_keys(2048)
        sk_f, pk_f = generate_keys(2048)
        voter = Voter("v1", sk_v, pk_v, sk_f, pk_f)
        cert_E = ca.generate_certificate("v1", pk_v)

        sk_ue, pk_ue = generate_keys(2048)
        cert_ue = ca.generate_certificate("UE", pk_ue)
        ca.publish_certificate("UE", cert_ue)

        # Registrazione FIDO2
        ch = sa.generate_registration_challenge("v1")
        sa.complete_registration("v1", pk_f, voter.respond_to_challenge(ch))

        # Fase 0
        t0 = time.perf_counter()
        cert_ae = ca.get_certificate("AE")
        pk_ae = ca.extract_public_key(cert_ae)
        pl = director.configure_election(pk_ae, ["A", "B"], ["Roma"], time.time(), 3600)
        ae.receive_params(pl, cert_dir)
        ae.add_voter("v1")
        ue = UE(sk_ue, pk_ue, ae.public_key, ["A", "B"])
        t_fase0 = (time.perf_counter() - t0) * 1000

        # Fase 1
        t0 = time.perf_counter()
        ch = sa.generate_auth_challenge("v1")
        sig = voter.respond_to_challenge(ch)
        sa.verify_authentication("v1", sig, cert_E)
        ap = sa.release_auth_proof("v1", ch, pk_v)
        voter.receive_auth_proof(ap)
        t_fase1 = (time.perf_counter() - t0) * 1000

        # Fase 2
        t0 = time.perf_counter()
        pk_ae2 = ca.extract_public_key(ca.get_certificate("AE"))
        req = voter.prepare_authorization_request(pk_ae2)
        pk_sa = ca.extract_public_key(ca.get_certificate("SA"))
        ae.receive_enablement_request(req, cert_E, pk_sa)
        et = ae.release_token("v1", pk_v)
        ek = ae.release_encryption_key(pk_v)
        resp = len(et).to_bytes(4,"big") + et + len(ek).to_bytes(4,"big") + ek
        voter.receive_ae_response(resp, pk_ae2)
        t_fase2 = (time.perf_counter() - t0) * 1000

        # Fasi 3-4
        t0 = time.perf_counter()
        ct = voter.prepare_ballot("A", pk_ue)
        rc = ue.receive_ballot(ct)
        voter.validate_receipt(rc, pk_ue)
        t_fase34 = (time.perf_counter() - t0) * 1000

        # Fase 5
        t0 = time.perf_counter()
        ekp = ae.send_private_key(pk_ue)
        ue.close_and_tally(ekp)
        t_fase5 = (time.perf_counter() - t0) * 1000

        return t_fase0, t_fase1, t_fase2, t_fase34, t_fase5

    print("\n  Esecuzione protocollo completo (1 elettore)...")
    separatore()

    risultati = [esegui_protocollo_completo() for _ in range(3)]

    fasi = ["Fase 0 (configurazione)", "Fase 1 (autenticazione)",
            "Fase 2 (abilitazione)", "Fasi 3-4 (scheda+trasmissione)",
            "Fase 5 (scrutinio)"]

    totali = []
    for i, fase in enumerate(fasi):
        tempi = [r[i] for r in risultati]
        media = statistics.mean(tempi)
        totali.append(media)
        print_risultato(f"  {fase}", media, min(tempi), max(tempi))

    separatore()
    print_risultato("  TOTALE protocollo", sum(totali), sum(totali), sum(totali), 0)


# =============================================================================
# 5. SCALABILITÀ AL CRESCERE DEGLI ELETTORI
# =============================================================================

def benchmark_scalabilita():
    print_header("5. SCALABILITÀ AL CRESCERE DEL NUMERO DI ELETTORI")

    def simula_n_elettori(n):
        """Simula n elettori che votano e misura i tempi chiave."""

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
        pl = director.configure_election(
            pk_ae, ["A", "B", "C"], ["Roma"], time.time(), 3600
        )
        ae.receive_params(pl, cert_dir)

        ue = UE(sk_ue, pk_ue, ae.public_key, ["A", "B", "C"])

        # Prepara n elettori
        voters = []
        for i in range(n):
            sk_v, pk_v = generate_keys(2048)
            sk_f, pk_f = generate_keys(2048)
            v = Voter(f"v{i}", sk_v, pk_v, sk_f, pk_f)
            cert_E = ca.generate_certificate(f"v{i}", pk_v)
            ae.add_voter(f"v{i}")
            ch = sa.generate_registration_challenge(f"v{i}")
            sa.complete_registration(f"v{i}", pk_f, v.respond_to_challenge(ch))
            voters.append((v, cert_E))

        # Misura tempo di voto per tutti gli elettori
        t_voto = time.perf_counter()
        for voter, cert_E in voters:
            ch = sa.generate_auth_challenge(voter.voter_id)
            sig = voter.respond_to_challenge(ch)
            sa.verify_authentication(voter.voter_id, sig, cert_E)
            ap = sa.release_auth_proof(voter.voter_id, ch, voter.pk)
            voter.receive_auth_proof(ap)

            pk_ae2 = ca.extract_public_key(ca.get_certificate("AE"))
            req = voter.prepare_authorization_request(pk_ae2)
            pk_sa = ca.extract_public_key(ca.get_certificate("SA"))
            ae.receive_enablement_request(req, cert_E, pk_sa)
            et = ae.release_token(voter.voter_id, voter.pk)
            ek = ae.release_encryption_key(voter.pk)
            resp = len(et).to_bytes(4,"big") + et + len(ek).to_bytes(4,"big") + ek
            voter.receive_ae_response(resp, pk_ae2)

            ct = voter.prepare_ballot("A", pk_ue)
            rc = ue.receive_ballot(ct)
            voter.validate_receipt(rc, pk_ue)
        t_voto_totale = (time.perf_counter() - t_voto) * 1000

        # Misura tempo scrutinio
        t_scrutinio = time.perf_counter()
        ekp = ae.send_private_key(pk_ue)
        ue.close_and_tally(ekp)
        t_scrutinio_totale = (time.perf_counter() - t_scrutinio) * 1000

        return t_voto_totale, t_voto_totale / n, t_scrutinio_totale

    print(f"\n  {'N elettori':>12} | {'Tempo totale voto':>18} | {'Tempo per elettore':>18} | {'Tempo scrutinio':>15}")
    separatore()

    for n in [1, 5, 10, 50, 1000]:
        t_tot, t_per, t_scr = simula_n_elettori(n)
        print(f"  {n:>12} | {t_tot:>15.0f} ms | {t_per:>15.0f} ms | {t_scr:>12.0f} ms")


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("\n" + "="*65)
    print("  BENCHMARK PROTOCOLLO VOTO ELETTRONICO")
    print("="*65)
    print(f"  Ogni misurazione ripetuta {RIPETIZIONI} volte (dove applicabile)")

    benchmark_primitive()
    benchmark_dimensioni()
    benchmark_verifiche()
    benchmark_fasi()
    benchmark_scalabilita()

    print("\n" + "="*65)
    print("  BENCHMARK COMPLETATO")
    print("="*65 + "\n")


if __name__ == "__main__":
    main()