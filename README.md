# 🗳️ Sistema di Votazione Elettronica Sicuro

**Algoritmi e Protocolli per la Sicurezza** — Progetto Finale sviluppato da 

Un'implementazione crittografica completa di un sistema di votazione elettronico pseudoanonimo, trasparente e verificabile, realizzato per una azienza ideale **Fantasy Company** con supporto a elezioni interne distribuite su più sedi operative.

---

## 📋 Sommario Esecutivo

Questo progetto realizza un **protocollo di voto elettronico sicuro** che garantisce simultaneamente:
- ✅ **Pseudoanonimato**: Nessuna entità può associare l'identità dell'elettore al voto espresso
- ✅ **Integrità**: I voti non possono essere alterati, rimossi o introdotti fraudolentemente
- ✅ **Autenticità**: Solo gli elettori legittimi possono votare (una sola volta)
- ✅ **Verificabilità individuale**: Ogni elettore può verificare che il proprio voto sia incluso nel conteggio
- ✅ **Verificabilità universale**: Chiunque può verificare la correttezza del risultato finale
- ✅ **Trasparenza**: Il sistema non si affida a meccanismi "scatola nera"

---

## 🎯 Obiettivi del Progetto

### Funzionalità Principale
Realizzare una **piattaforma di votazione elettronica** versatile e riutilizzabile che supporti:
- Elezioni di **qualsiasi ruolo interno** (manager, direttore, segretario)
- **Sedi multiple** distribuite sul territorio nazionale
- **Elezioni ripetute** nel tempo con lista degli elettori variabile
- **Modifica/annullamento del voto** prima della chiusura delle urne (protezione da coercizione locale)

### Scelta tipologia di elezione: First-Past-the-Post


## 🏗️ Struttura del Progetto

Il progetto è organizzato in **4 Work Package (WP)** secondo la metodologia proposta:

### **WP1 – Modello** 📐
Definizione completa della funzionalità, threat model e requisiti del sistema.

**Contenuti:**
- Tipologia di votazione scelta (First-Past-the-Post)
- **7 Attori onesti** del sistema (Direttore, AE, Elettore, UE, SA, CA, RPE)
- **11 Requisiti funzionali** (RF1–RF11)
- **6 Requisiti non funzionali** (RNF1–RNF6)
- **Threat model** con avversari interni, esterni e collusioni
- **Proprietà di sicurezza** richieste

---

### **WP2 – Soluzione/Protocollo** 🔐
Descrizione dettagliata del protocollo crittografico in 6 fasi principali.

**Contenuti:**
- **Fase 0**: Configurazione dell'elezione (parametri, candidati, chiavi)
- **Fase 1**: Autenticazione dell'elettore (FIDO2 + challenge/response)
- **Fase 2**: Abilitazione al voto (generazione token univoco firmato)
- **Fase 3**: Preparazione della scheda (cifratura asimmetrica)
- **Fase 4**: Trasmissione e validazione (RSA-OAEP, verifica firma, controllo nonce)
- **Fase 5**: Scrutinio (decifratura con Kpriv_cifr, costruzione Merkle Tree)
- **Fase 6**: Verifica individuale e universale


---

### **WP3 – Analisi della Sicurezza** 🛡️
Verifica formale e informale che il protocollo soddisfi le proprietà di sicurezza.

**Contenuti:**
- Analisi di resistenza rispetto al threat model
- **7 scenari di attacco** simulati
- Discussione di compromessi architetturali
- Identificazione di **limiti dichiarati**

---

### **WP4 – Implementazione e Prestazioni** 💻
Implementazione Python con misurazioni sperimentali di efficienza.

**Contenuti:**
- Implementazione del protocollo in Python
- **Dati di costo computazionale** (operazioni crittografiche)
- **Misurazioni di latenza** per fase
- **Analisi di scalabilità** (O(n) lineare per fase votazione)
- **Simulazione interattiva** della cabina elettorale
- **Simulazione degli attacchi** (7 scenari)

---

## 📂 Struttura dei File
---

ProgettoAPS_gruppo4/
├── WP4/
│   ├── src/
│   │   ├── main.py                          # Simulazione completa del protocollo
│   │   ├── attacks.py                       # Attacchi al protocollo e contromisure
│   │   │
│   │   ├── Actors/
│   │   │   ├── CertificationAuthority.py    # Autorità di Certificazione (CA)
│   │   │   ├── AuthenticationSystem.py      # Sistema di Autenticazione (SA)
│   │   │   ├── ElectionAuthority.py         # Autorità Elettorale (AE)
│   │   │   ├── Director.py                  # Direttore Elettorale (D)
│   │   │   ├── Voter.py                     # Elettore (E)
│   │   │   └── ElectronicBallotBox.py       # Urna Elettronica (UE)
│   │   │
│   │   └── Utils/
│   │       ├── crypto.py                    # Primitive crittografiche (RSA-OAEP, RSA-PSS, SHA-256)
│   │       └── MerkleTree.py                # Struttura Merkle Tree per verifica schede
│   │
│   └── docs/
│       ├── source/
│       │   ├── conf.py                      # Configurazione Sphinx
│       │   └── index.rst                    # Indice documentazione
│       └── build/                           # Output HTML generato
│
├── Relazione.pdf                            # Relazione tecnica del progetto
├── README.md                                # Questo file
├── .gitignore                               # File da escludere da Git
└── .gitattributes                           # Configurazione attributi Git
```
