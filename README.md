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

`LICENSE_ADMIN_KEY` deve rimanere esclusivamente su questo server e serve per creare o revocare licenze.

## Avvio

```bash
docker compose up --build -d
docker compose ps
curl http://127.0.0.1:8001/health
```

Il bind predefinito e' `127.0.0.1:8001`: pubblicare il servizio con nginx, Traefik o un altro reverse proxy dotato di certificato TLS valido per `licenze.ghome.it`. Se il reverse proxy gira in un altro container, impostare un indirizzo o una rete Docker compatibile con quella configurazione.

## Portainer Git stack

- Repository: `https://github.com/RazorCopter/Autify-LICENSE.git`
- Reference: `refs/heads/main`
- Compose path: `docker-compose.yml`
- Variabili obbligatorie: `LICENSE_SHARED_SECRET`, `LICENSE_ADMIN_KEY`
- Se Portainer deve raggiungere la porta pubblicata dall'host, impostare `LICENSE_BIND_ADDRESS=0.0.0.0` e limitarne l'accesso tramite firewall/reverse proxy.

## API operative

- `GET /health`: health check pubblico.
- `POST /admin/licenses`: crea una licenza, richiede header `X-License-Admin-Key`.
- `POST /admin/licenses/revoke`: revoca una licenza, richiede lo stesso header.
- `POST /activate`: attivazione cifrata da parte di un'istanza Autify.
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