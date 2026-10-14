# CTI Auto Collector v4.0 - Multi-Type IOC Collection & Context

Tool open-source di **raccolta automatica, passiva e in sola lettura** di indicatori *segnalati da fonti pubbliche*. Prosegue il progetto originale di IOC enrichment/pivoting; non richiede indicatori manuali e usa esclusivamente la libreria standard Python 3.11+.

> **ATTENZIONE:** un IOC presente in un feed NON dimostra un contatto con la rete dell'utente, un incidente, la malevolenza persistente di un IP né un'attribuzione. È necessaria una verifica umana del perimetro, della data e della provenienza prima di qualsiasi decisione operativa.

## Avvio Windows (nessun pip)

1. Aprire CMD nella cartella contenente `CTI_Auto_Collector.py`.
2. Lanciare:

```cmd
py -3.11 CTI_Auto_Collector.py
```

I file vengono generati nella directory `CTI_Risultati`. Nessun URL, file malware o host indicato dalle fonti viene visitato direttamente: vengono contattati solo gli endpoint dei provider approvati nel codice. Se nessuna fonte restituisce indicatori, il programma lo segnala ed esce con codice 2.

Per eseguire i test riproducibili **senza accesso Internet**:

```cmd
py -3.11 -m unittest -v test_collector
```

Su altri sistemi: `python3 CTI_Auto_Collector.py`.

## Che cosa raccoglie

Tipologie supportate quando una fonte fornisce dati pertinenti:

- Indirizzi **IP** (IPv4 e IPv6 globali), **CIDR** (senza espansione), **domini**, **URL**, **IP:porta**, **dominio:porta**.
- Hash **MD5**, **SHA-1**, **SHA-256** e **SHA-512** (validati); la presenza effettiva dipende dai provider disponibili. Il supporto di un tipo **non garantisce** la presenza di record per quel tipo in ogni run.
- Informazioni su **CISA KEV/EPSS** tenute **separate dagli IOC**.

### Feed senza credenziali (raccolta automatica)

| Fonte | Informazioni | Note |
|---|---|---|
| CERT Polska Warning List | Domini segnalati, lista ufficiale | Solo presenza nella lista; non affermazione di compromissione locale |
| Phishing.Database | URL e domini aggiunti oggi | Può restituire 0 record se non ci sono nuove segnalazioni; fonti dello stesso editore |
| Phishunt | Domini phishing segnalati | **Aggregatore**: non è conferma indipendente da feed usati a monte |
| Feodo Tracker | IP C2 segnalati | Può avere 0 record |
| Emerging Threats Compromised | IP segnalati compromessi | Fonte esterna, non detection locale |
| Emerging Threats Block | IP/reti CIDR | Le reti rimangono CIDR |
| Blocklist.de | IP segnalati | Indicazioni temporali del provider; non malevolenza permanente |
| IPsum | IP da liste aggregate | Conteggio upstream senza conferma indipendente |
| Spamhaus DROP | CIDR | Rispetta attribution, cache 24h, no espansione |
| CISA KEV | CVE sfruttate | Intelligence vulnerabilità, NON IOC |
| FIRST EPSS | Valutazione statistica per CVE | Non è un indice di exploit confermato su un singolo asset |
| RIPEstat | ASN e routing per IP selezionati | Contesto BGP, NON reputazione |
| GreyNoise Community | Contesto IP per campione | Quote e condizioni del provider |

Il feed OpenPhish è **disabilitato per impostazione predefinita**. In ricerca personale/non commerciale, e solo se autorizzata dai relativi termini, attivare `--enable-openphish`. I dati del feed non devono essere redistribuiti senza i diritti necessari.

### API opzionali (chiavi personali)

- `ABUSECH_AUTH_KEY`: abilita **ThreatFox** (IOC tra cui domain, URL, IP:porta, hash) e **MalwareBazaar** (hash campioni, se disponibili nel JSON). La chiave è gratuita per gli usi ammessi dal servizio, soggetta ai termini di abuso.ch.
- `VT_API_KEY`: abilita lookups **passivi** su VirusTotal per IP, domini, URL e hash. **Non** effettua scansioni, invii di file né analisi attive. La quota può impedire alcuni endpoint.
- `REQUESTS_CA_BUNDLE` o `SSL_CERT_FILE`: percorso CA PEM **approvata dall'IT** per HTTPS con proxy aziendale. Il programma non consente di disabilitare la verifica TLS.

CMD Windows (per la singola sessione):

```cmd
set ABUSECH_AUTH_KEY=LA_TUA_CHIAVE_PRIVATA
set VT_API_KEY=LA_TUA_CHIAVE_PRIVATA
py -3.11 CTI_Auto_Collector.py
```

**Non committare API key, screenshot con chiavi, log o output reali dei provider nel repository pubblico.** Le chiavi eventualmente presenti in vecchi script vanno revocate/ruotate.

## Formato degli output (cartella CTI_Risultati)

- `CTI_Findings.xlsx` — **18 fogli**: `Dashboard`, `IOC_INDEX`, **10 fogli `IOC_<TIPO>`**, `Observations`, `Correlations`, `Relations`, `Enrichment`, `Sources`, `CISA_KEV`. I fogli dei tipi senza dati mantengono almeno l'intestazione: non vengono creati IOC fittizi.
- `unique_indicators.csv` — una riga per coppia (tipo, valore), tutte le fonti, famiglia dei publisher, classificazioni, data `first_seen` solo se nota, riferimenti.
- `IOC_per_tipo/` — dieci CSV, uno per tipo, con gli stessi campi dell'indice e gli indicatori univoci.
- `indicators.csv` — osservazioni **distinte per fonte**, dunque uno stesso IOC può apparire più volte: non è un bug.
- `correlations.csv` — solo **corrispondenze esatte** di tipo+valore tra feed. `source_count` ≠ prove indipendenti; `direct_publisher_count` esclude aggregatori noti, ma neppure publisher diversi garantiscono indipendenza delle fonti upstream.
- `relations.csv` — **relazioni contestuali** tra IP inclusi in una rete CIDR segnalata, e URL il cui hostname compare tra i domini segnalati. **Queste NON aumentano il numero di IOC corroborati.**
- `enrichment.csv` — risposte provider e loro stato, senza assegnazione automatica di punteggi o verdetti locali.
- `vulnerabilities.csv`, `sources.csv`, `analysis.json`, `CTI_Report.docx`, `charts/`.

## Correlazione e provenienza

1. Normalizza indicatori per tipo, senza espandere reti né inventare campi `first_seen`.
2. Deduplica l'identica osservazione **nella stessa fonte**, preservando una osservazione per fonte distinta.
3. Crea l'indice univoco per (tipo, valore): fonti, riferimenti, classe dichiarata e raggruppamento degli editori.
4. Evidenzia le sovrapposizioni esatte (`Correlations`) e, **separatamente**, le relazioni `ip_within_reported_cidr` e `url_host_matches_reported_domain` (`Relations`).
5. Seleziona un campione di IP per RIPEstat/GreyNoise e, se abilitato, IOC di più categorie per VirusTotal, applicando limiti di interrogazione.

Le sovrapposizioni possono dipendere dalla stessa fonte a monte. Non esiste alcuna funzione di rilevazione di incidenti sul perimetro aziendale né un caricamento automatico MISP. Non esistono falsi "risk score" derivati dal numero di liste.

## Parametri utili

```cmd
py -3.11 CTI_Auto_Collector.py --help
py -3.11 CTI_Auto_Collector.py --limit 4000 --ripe-limit 80 -o CTI_Risultati
py -3.11 CTI_Auto_Collector.py --gn-limit 0 --vt-limit 0
```

## Stato delle verifiche

- Suite automatica **offline con risposte HTTP sintetiche** per normalizzazione, correlazioni, relazioni, output e integrazioni simulate.
- Retrocompatibilità logica dell'export verificata sul dataset della v3.0 fornito per i test, **non incluso nel repository** per motivi di licenza e riservatezza.
- **Non sono state eseguite da questo ambiente chiamate live alle tre nuove fonti**. Eseguire sul PC locale e controllare `Sources`/`sources.csv` prima di proclamare la verifica end-to-end.

## Licenze e crediti

Codice sotto MIT, dati dei provider soggetti ai **rispettivi termini**. Il progetto non promette l'approvazione dei crediti EC-Council: *Author Security Tool* richiede paternità dimostrabile, pubblicazione open-source e verifica/feedback della comunità. Un repo GitHub pubblico non garantisce da solo i crediti.

Collegamenti di riferimento: [CERT Polska](https://cert.pl/en/warning-list/), [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database), [Phishunt](https://github.com/0xDanielLopez/phishunt-feed), [ThreatFox](https://threatfox.abuse.ch/api/), [MalwareBazaar](https://bazaar.abuse.ch/), [VirusTotal](https://docs.virustotal.com/reference/overview), [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/).


## Author and Maintainer

Francesco Galossi (GitHub: [@tnbrs96](https://github.com/tnbrs96))

CTI Auto Collector is an open-source project based on
original Python CTI scripts, subsequently consolidated
and validated with AI-assisted development.

Project maintenance, testing and publication are
managed through the GitHub account @tnbrs96.
