"""
Modulo che implementa l'Autorità Elettorale (AE).

Responsabilità:
    - Ricezione e validazione dei parametri elettorali dal Direttore (Fase 0)
    - Generazione della coppia di chiavi per la cifratura dei voti (Fase 0)
    - Verifica del diritto di voto e rilascio del token di abilitazione (Fase 2)
    - Trasmissione di K_priv_cifr all'UE dopo la chiusura delle urne (Fase 5)

Interazioni:
    - Fase 0: riceve parametri dal Direttore
    - Fase 2: riceve richiesta di abilitazione dall'elettore
    - Fase 5: trasmette K_priv_cifr all'UE
"""

import os
from cryptography.hazmat.primitives import serialization
from crypto import generate_keys, sign, verify, encrypt_chunked, decrypt_chunked


class ElectionAuthority:

    def __init__(self, ca):
        """
        Inizializza l'Autorità Elettorale.
        Genera la propria coppia di chiavi RSA e si registra nella PKI.

        :param ca: istanza della CertificationAuthority aziendale
        """
        self._private_key, self.public_key = generate_keys(2048)
        self._ca = ca

        # Genera e pubblica il proprio certificato nella PKI
        self._certificate = ca.generate_certificate("AE", self.public_key)
        ca.publish_certificate("AE", self._certificate)

        # Parametri elettorali ricevuti dal Direttore
        self._params = None             # messaggio M
        self._electorate = set()        # insieme L degli aventi diritto
        self._t_open = None             # apertura urne
        self._t_close = None            # chiusura urne
        self._candidates = None         # lista candidati C

        # Coppia di chiavi per la cifratura dei voti
        self._k_priv_cifr = None
        self.k_pub_cifr = None

        # Registro degli elettori abilitati: entity_id -> True
        self._enabled_voters = {}

    # -------------------------------------------------------------------------
    # FASE 0 — RICEZIONE PARAMETRI DAL DIRETTORE
    # -------------------------------------------------------------------------

    def receive_params(self, encrypted_payload, cert_dir):
        """
        Fase 0.
        Decifra il payload ricevuto dal Direttore, verifica la firma
        e inizializza la sessione elettorale.

        Il payload cifrato contiene: M || sigma_M
        dove M = (t_open || t_close || candidati || sedi)

        :param encrypted_payload: Enc_pkAE(M || sigma_M) (bytes)
        :param cert_dir: certificato digitale del Direttore
        :raises ValueError: se il certificato o la firma non sono validi
        """
        # Verifica il certificato del Direttore tramite la CA
        if not self._ca.verify_certificate(cert_dir):
            raise ValueError("Certificato del Direttore non valido")

        # Verifica che il Subject del certificato corrisponda al Direttore
        if cert_dir["entity_id"] != "Direttore":
            raise ValueError(
                "Il certificato non appartiene al Direttore autorizzato"
            )

        # Decifra il payload con sk_AE tramite chunking
        # (M || sigma_M può superare il limite di 190 bytes di RSA-OAEP)
        try:
            payload = decrypt_chunked(self._private_key, encrypted_payload)
        except ValueError:
            raise ValueError("Decifratura del payload fallita")

        # Estrae M e sigma_M dal payload
        # Convenzione: ultimi 256 bytes = firma RSA (2048 bit)
        sigma_M = payload[-256:]
        M = payload[:-256]

        # Verifica la firma del Direttore su M
        pk_dir = self._ca.extract_public_key(cert_dir)
        if not verify(pk_dir, sigma_M, M):
            raise ValueError(
                "Firma del Direttore non valida: parametri alterati"
            )

        # Deserializza i parametri elettorali
        self._params = M
        self._init_session(M)

    def _init_session(self, M):
        """
        Inizializza la sessione elettorale a partire dai parametri ricevuti.
        Determina l'elettorato legittimo e genera la coppia di chiavi
        per la cifratura dei voti.

        :param M: parametri elettorali in bytes (JSON serializzato)
        """
        # Deserializza M — formato JSON dal Direttore
        import json
        params = json.loads(M.decode())
        self._t_open     = params["T_open"]
        self._t_close    = params["T_close"]
        self._candidates = params["candidates"]
        offices          = params.get("authorized_offices", [])

        # Determina l'elettorato legittimo L dalle sedi autorizzate
        self._electorate = self._get_electorate(offices)

        # Genera la coppia di chiavi per la cifratura dei voti
        self._k_priv_cifr, self.k_pub_cifr = generate_keys(2048)


    def _get_electorate(self, offices):
        """
        Ricava l'insieme degli elettori legittimi L dalle sedi autorizzate.
        In una simulazione restituisce un insieme predefinito.

        :param offices: lista delle sedi autorizzate
        :returns: insieme degli entity_id degli elettori legittimi
        """
        # TODO: accedere ad un database in cui vi sono indicati 
        # i dipendenti per ogni sede aziendale presente in offices
        return set()


    def add_voter(self, entity_id):
        """
        Aggiunge un elettore all'elettorato legittimo L.
        Usato in fase di setup della simulazione.

        :param entity_id: identificativo dell'elettore da aggiungere
        """
        self._electorate.add(entity_id)

    # -------------------------------------------------------------------------
    # FASE 2 — ABILITAZIONE E RILASCIO TOKEN
    # -------------------------------------------------------------------------

    def receive_enablement_request(self, encrypted_auth_proof, cert_E, pk_SA):
        """
        Fase 2 - passi 2 e 3.
        Decifra la prova di autenticazione, ne verifica la firma
        tramite pk_SA e controlla che l'elettore abbia diritto al voto.

        Il payload decifrato contiene: entity_id || challenge || sigma_auth_proof

        :param encrypted_auth_proof: Enc_pkAE(entity_id || challenge || sigma)
        :param cert_E: certificato digitale dell'elettore
        :param pk_SA: chiave pubblica del SA (recuperata dalla PKI)
        :returns: entity_id dell'elettore se abilitato
        :raises ValueError: se la verifica fallisce
        """
        # Verifica il certificato dell'elettore
        if not self._ca.verify_certificate(cert_E):
            raise ValueError("Certificato dell'elettore non valido")

        # Decifra la prova di autenticazione tramite chunking
        # (entity_id || challenge || sigma può superare 190 bytes)
        try:
            payload = decrypt_chunked(self._private_key, encrypted_auth_proof)
        except ValueError:
            raise ValueError("Decifratura della prova di autenticazione fallita")

        # Estrae entity_id, challenge e sigma_auth_proof
        # Convenzione: entity_id(lunghezza variabile) || challenge(32) || firma(256)
        sigma_auth_proof = payload[-256:]
        challenge = payload[-288:-256]
        entity_id = payload[:-288].decode()

        # Verifica la firma del SA su (entity_id || challenge)
        message = entity_id.encode() + challenge
        if not verify(pk_SA, sigma_auth_proof, message):
            raise ValueError(
                "Firma del SA non valida: prova di autenticazione alterata"
            )

        # Verifica che l'elettore abbia diritto al voto
        if entity_id not in self._electorate:
            raise ValueError(
                f"Elettore {entity_id} non presente nell'elettorato legittimo"
            )

        # Verifica che l'elettore non sia già stato abilitato
        if entity_id in self._enabled_voters:
            raise ValueError(
                f"Elettore {entity_id} ha già ottenuto un'abilitazione "
                f"in questa sessione"
            )

        # Marca l'elettore come abilitato
        self._enabled_voters[entity_id] = True
        return entity_id
    

    def release_token(self, entity_id, pk_E):
        """
        Fase 2 - passo 4.
        Genera un token monouso, lo firma con sk_AE
        e lo cifra con pk_E.

        :param entity_id: identificativo dell'elettore abilitato
        :param pk_E: chiave pubblica RSA dell'elettore
        :returns: Enc_pkE(token_id || sigma_token) (bytes)
        :raises ValueError: se l'elettore non è abilitato
        """
        if entity_id not in self._enabled_voters:
            raise ValueError(f"Elettore {entity_id} non abilitato")

        # Genera token monouso di 256 bit
        token_id = os.urandom(32)

        # Firma il token con sk_AE
        sigma_token = sign(self._private_key, token_id)

        # Cifra (token_id || sigma_token) con pk_E tramite chunking
        # (token_id 32B + sigma_token 256B = 288B > limite 190B)
        payload = token_id + sigma_token
        return encrypt_chunked(pk_E, payload)



    def release_encryption_key(self, pk_E):
        """
        Fase 2 - passo 5.
        Firma K_pub_cifr con sk_AE e la cifra con pk_E.

        :param pk_E: chiave pubblica RSA dell'elettore
        :returns: Enc_pkE(K_pub_cifr || sigma_Kpub) (bytes)
        """
        

        # Serializza K_pub_cifr in bytes
        k_pub_cifr_bytes = self.k_pub_cifr.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Firma K_pub_cifr con sk_AE
        sigma_kpub = sign(self._private_key, k_pub_cifr_bytes)

        # Cifra (K_pub_cifr || sigma_Kpub) con pk_E tramite chunking
        # (K_pub_cifr PEM ~450B + sigma 256B > limite 190B)
        payload = k_pub_cifr_bytes + sigma_kpub
        return encrypt_chunked(pk_E, payload)

    # -------------------------------------------------------------------------
    # FASE 5 — TRASMISSIONE K_PRIV_CIFR ALL'UE
    # -------------------------------------------------------------------------

    def send_private_key(self, pk_UE):
        """
        Fase 5 - passo 1.
        Cifra K_priv_cifr con pk_UE e la trasmette all'UE
        dopo la chiusura delle urne T_close.

        :param pk_UE: chiave pubblica RSA dell'UE
        :returns: Enc_pkUE(K_priv_cifr) (bytes)
        """

        # Serializza K_priv_cifr in bytes
        k_priv_cifr_bytes = self._k_priv_cifr.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Cifra K_priv_cifr con pk_UE tramite chunking
        # (K_priv_cifr PEM ~1700B >> limite 190B)
        return encrypt_chunked(pk_UE, k_priv_cifr_bytes)