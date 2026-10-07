# Autify-LICENSE

Server licenze centralizzato per le installazioni Autify on-premise.

Il repository espone un solo container FastAPI con database SQLite persistente. Le installazioni cliente comunicano con questo servizio tramite HTTPS; i payload applicativi sono inoltre cifrati con AES-256-GCM usando `LICENSE_SHARED_SECRET`.

## Architettura

```text
Autify cliente (autify-api) -- HTTPS --> licenze.ghome.it
                                            |
                                    autify-license-server
                                            |
                                      volume SQLite
```

## Configurazione

1. Copiare `.env.example` in `.env`.
2. Generare due segreti distinti:

   ```bash
   openssl rand -hex 32
   openssl rand -hex 32
   ```

3. Assegnare il primo a `LICENSE_SHARED_SECRET` e il secondo a `LICENSE_ADMIN_KEY`.
4. Configurare lo stesso `LICENSE_SHARED_SECRET` negli stack Autify cliente.

`LICENSE_ADMIN_KEY` deve rimanere esclusivamente su questo server e serve per gestire le licenze. Viene inoltre usata per derivare la chiave AES-256-GCM che protegge i codici licenza archiviati: modificarla rende irrecuperabili i codici gia' memorizzati, pur lasciando invariata la validazione tramite hash. La dashboard la invia al server solo durante il login e riceve un cookie di sessione `HttpOnly`; la chiave non viene memorizzata nel browser.

Le sessioni amministrative durano 8 ore per impostazione predefinita. La durata puo' essere configurata con `LICENSE_ADMIN_SESSION_HOURS` (da 1 a 168 ore). `LICENSE_ADMIN_COOKIE_SECURE` deve restare `true` quando il servizio e' pubblicato in HTTPS; puo' essere impostato a `false` esclusivamente durante test locali in HTTP.

## Avvio

```bash
docker compose up --build -d
docker compose ps
curl http://127.0.0.1:8001/health
```

Il bind predefinito e' `127.0.0.1:8001`: pubblicare il servizio con nginx, Traefik o un altro reverse proxy dotato di certificato TLS valido per `licenze.ghome.it`. Se il reverse proxy gira in un altro container, impostare un indirizzo o una rete Docker compatibile con quella configurazione.

## Dashboard amministrativa

La dashboard e' disponibile sullo stesso servizio:

```text
https://licenze.ghome.it/admin/
```

Consente di:

- consultare i contatori e l'elenco delle licenze;
- filtrare per azienda, piano e stato;
- generare licenze da 1, 6 o 12 mesi oppure a vita;
- mostrare, nascondere e copiare i codici generati dal server a partire dalla versione 1.2.0;
- revocare, rilasciare o eliminare definitivamente una licenza.

I nuovi codici completi sono conservati cifrati con AES-256-GCM e sono recuperabili esclusivamente da un amministratore autenticato. L'hash continua a essere usato per la validazione. Le licenze create prima della versione 1.2.0 conservano soltanto hash e suffisso, quindi il loro codice completo non e' recuperabile. Gli elenchi e i dettagli API non espongono mai il codice: indicano soltanto `code_available`, mentre il recupero avviene tramite un endpoint amministrativo dedicato.

L'eliminazione e' permanente. Per evitare operazioni accidentali, una licenza attiva richiede una seconda conferma nella dashboard e il parametro esplicito `force=true` nell'API.

Le sessioni della dashboard sono conservate in memoria. Un riavvio del container disconnette gli amministratori senza influire sulle licenze. E' comunque raccomandato proteggere `/admin/` con Cloudflare Access, VPN o un controllo equivalente a livello di reverse proxy.

Gli endpoint amministrativi continuano ad accettare l'header `X-License-Admin-Key` per automazioni e integrazioni server-to-server.

## Portainer Git stack

- Repository: `https://github.com/RazorCopter/Autify-LICENSE.git`
- Reference: `refs/heads/main`
- Compose path: `docker-compose.yml`
- Variabili obbligatorie: `LICENSE_SHARED_SECRET`, `LICENSE_ADMIN_KEY`
- Se Portainer deve raggiungere la porta pubblicata dall'host, impostare `LICENSE_BIND_ADDRESS=0.0.0.0` e limitarne l'accesso tramite firewall/reverse proxy.

## API operative

- `GET /health`: health check pubblico.
- `POST /admin/licenses`: crea una licenza, richiede header `X-License-Admin-Key`.
- `GET /v1/admin/licenses/{code_suffix}/code`: recupera il codice completo cifrato a riposo, se disponibile.
- `DELETE /v1/admin/licenses/{code_suffix}`: elimina definitivamente una licenza; richiede `force=true` se attiva.
- `POST /admin/licenses/revoke`: revoca una licenza, richiede lo stesso header.
- `POST /activate`: attivazione cifrata da parte di un'istanza Autify.
- `POST /v1/deactivate`: permette a un'installazione on-premise di rilasciare autonomamente la propria licenza. Il codice torna disponibile per una nuova attivazione.
- `POST /validate`: validazione cifrata da parte di un'istanza Autify.

Consultare il codice e i test in `license_server/tests` per i payload amministrativi aggiornati.

## Test

```bash
python -m pip install -r license_server/requirements-test.txt
python -m pytest license_server/tests -q
cd license_server
python -m pytest tests -q

## Backup

Il database si trova nel volume Docker `autify_license_data` al percorso `/data/licenses.db`. Effettuare backup regolari del volume. Per una copia consistente, fermare brevemente il container o usare gli strumenti SQLite appropriati.