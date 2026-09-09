# Review di auth-kademlia-rs — handoff per Codex

## Repository e ambito

- Repository: <https://github.com/fratrung/auth-kademlia-rs>
- Branch esaminato: `fix/dht-protocol-hardening`
- Commit esaminato: `4eef5213c09dc67c1fa5bd189100582acd14b618`
- Destinatario: code agent Codex, anche con GPT 5.6 Sol.
- Questo documento riporta la review precedente e la organizza in rilievi verificabili, indicazioni di correzione e criteri di accettazione. Non è una nuova verifica del branch al 9 settembre 2026.

## Esito e limiti della review originale

Sono emersi problemi concreti di correttezza e possibili colli di bottiglia. Il branch esaminato non è stato considerato pronto per un impiego affidabile come registro di identità senza ulteriori correzioni e verifiche.

La repository è stata clonata nella sandbox. Sono stati letti README, AGENTS, documentazione sulla resilienza, moduli Rust inclusi crittografia e binding Python, e test pertinenti.

La verifica è **statica**:

- `cargo test --all-targets` non è stato eseguito con successo: `cargo` non era installato.
- Il tentativo di raggiungere il server di distribuzione del toolchain è terminato in timeout.
- Non sono stati eseguiti test Rust, benchmark o misure di throughput, latenza e consumo di memoria.
- Il controesempio di routing è stato verificato mediante una ricostruzione fedele dell'algoritmo in Python, non eseguendo il codice Rust.
- L'incoerenza del limite dei frammenti è stata verificata aritmeticamente.
- La repository non è stata modificata durante la review.

I test proposti di seguito sono **da implementare ed eseguire**: non sono risultati già ottenuti. Le stime di memoria derivano dalle copie visibili nel codice e non sono misure di RSS.

## Istruzioni per l'agente che prende in carico il documento

1. Leggi `README.md`, `AGENTS.md` e gli eventuali AGENTS annidati applicabili prima di lavorare.
2. Controlla branch, commit e modifiche locali. I riferimenti di questa review sono relativi allo snapshot indicato; le righe potrebbero essere cambiate.
3. Rivalida ciascun rilievo sul codice corrente. Se non è più applicabile, documenta la correzione già presente o la ragione tecnica; non introdurre modifiche per far corrispondere il codice alla review.
4. Se l'incarico dell'utente comprende le correzioni, procedi con modifiche mirate e test di regressione. Questo documento, da solo, non richiede pubblicazione, push, merge o modifica delle impostazioni della repository.
5. Mantieni distanza XOR a 160 bit, verifica DID–chiave prima della cache, isolamento delle verifiche issuer/self-signed, budget dello storage e protezioni già presenti.
6. Non mantenere guardie dello storage o del routing attraverso attese di rete o verifica crittografica. Evita di risolvere i problemi creando un numero illimitato di task.
7. Rispetta i vincoli di compatibilità e di formato record. In particolare, AGENTS vieta di aggiungere arbitrariamente un timestamp `updated` ai DID Document: la soluzione al replay della Status List richiede una scelta esplicita sul protocollo, non l'introduzione automatica di quel campo.
8. Per i test di rete usa porte libere secondo AGENTS; usa porte effimere quando compatibile con l'infrastruttura dei test.
9. Riporta separatamente: problemi confermati, problemi corretti, problemi non riprodotti, decisioni di protocollo ancora necessarie e test effettivamente eseguiti.

## Priorità

| ID | Priorità della review | Problema |
| --- | --- | --- |
| R01 | Alta | UPDATE non atomico rispetto alla verifica dell'autorizzazione |
| R02 | Alta | Replay di una precedente Status List firmata |
| R03 | Alta | Selezione di vicini XOR non corretta |
| R04 | Alta | Rotazioni parziali senza recupero automatico affidabile |
| R05 | Alta su embedded | Copie integrali dello storage per le statistiche |
| R06 | Media/alta | Replica verso un peer lento ostacola la scoperta degli altri |
| R07 | Media | `stop()` lascia il nodo attivo e `Leave` attende una risposta inesistente |
| R08 | Media | Verifiche crittografiche bloccano il consumo delle code dei worker |
| R09 | Da rivalutare secondo la politica di rotazione issuer | Cache non invalidata al cambio della chiave issuer |
| R10 | Circoscritta | I contatti noti non aggiornano l'ordine LRU |
| R11 | Circoscritta | Le RPC cancellate possono lasciare voci in `pending` |
| R12 | Circoscritta | Limite dei frame incoerente fra mittente e ricevente |

## R01 — UPDATE non atomico rispetto all'autorizzazione

**Riferimenti:** `src/protocol.rs`, `rpc_update`, righe 714–746; `src/network.rs`, `update` e commit locale in `update_digest`.

[Codice dello snapshot](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/protocol.rs#L714-L746)

### Problema

`rpc_update` legge il valore corrente, verifica l'autorizzazione in `spawn_blocking`, quindi scrive il nuovo valore senza verificare che quello corrente sia ancora il valore usato per autorizzare l'operazione. Un altro UPDATE può modificare lo storage durante l'attesa.

Due aggiornamenti autorizzati dalla stessa vecchia chiave possono superare entrambi la verifica e sovrascriversi. Un aggiornamento ritardato può essere applicato dopo che quella chiave è stata sostituita. Non si tratta della possibilità di inventare una firma: il difetto è applicare un'autorizzazione validata contro uno stato non più corrente.

Lo stesso principio va verificato nel percorso di commit locale di `Server::update`. L'atomicità del singolo `DashMap::set` non protegge la sequenza lettura–verifica–scrittura.

### Correzione suggerita e accettazione

- Introdurre una scrittura condizionata al valore precedentemente verificato, tramite compare-and-swap o meccanismo equivalente per chiave.
- Mantenere atomici controllo del predecessore, aggiornamento del valore e contabilità del budget.
- Non mantenere un lock globale durante `spawn_blocking` o RPC.
- Aggiungere un test deterministico con due UPDATE concorrenti, usando barriere per imporre l'interleaving: una scrittura autorizzata sul vecchio stato non deve sovrascrivere uno stato successivo.
- Verificare sia `rpc_update` sia il commit locale dell'API `Server`.

## R02 — Replay della Status List

**Riferimento:** `src/protocol.rs`, `rpc_update_status_list`, righe 770–799.

[Codice dello snapshot](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/protocol.rs#L770-L799)

### Problema

Il codice controlla che il record esista e che il payload ricevuto abbia una firma valida dell'issuer, poi lo sostituisce. Non controlla un avanzamento autenticato dello stato.

Un soggetto in possesso di una lista precedente, firmata dallo stesso issuer ancora autorizzato, può reinviarla e ripristinare uno stato precedente, potenzialmente annullando revoche. Non serve la chiave privata. Un quorum non impedisce il replay se tutte le repliche accettano la stessa lista obsoleta.

### Correzione suggerita e accettazione

- Definire una regola autenticata di avanzamento della Status List, verificata atomicamente.
- Rivalutare formato, compatibilità e vincoli di AGENTS prima di scegliere il meccanismo. Non applicare automaticamente ai DID Document nuovi campi o timestamp.
- Test: applicare `S1`, poi `S2`, quindi reinviare `S1` con la sua firma originale. Il nodo deve rifiutare il ritorno allo stato precedente.
- Verificare anche aggiornamenti concorrenti e comportamento sulle repliche.

## R03 — Vicini XOR selezionati in modo errato

**Riferimenti:** `src/routing.rs`, costruzione di `TableTraverser`, righe 232–235; `find_neighbors`, righe 356–377.

[Attraversamento](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/routing.rs#L232-L235) · [Selezione](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/routing.rs#L356-L377)

### Problema e controesempio

`left_buckets` viene invertito e successivamente consumato con `pop()`: viene visitato prima il bucket sinistro più lontano. `find_neighbors` si ferma dopo `k` candidati e solo successivamente li ordina. L'ordinamento non può recuperare i contatti più vicini già esclusi.

Controesempio verificato nella ricostruzione Python: ciascun ID è il byte indicato seguito da 19 byte zero.

| Parametro | Valore |
| --- | --- |
| Nodo locale | `80` |
| `k` | `2` |
| Contatti, in ordine di inserimento | `10`, `20`, `90`, `a0`, `c0` |
| Target | `e0` |
| Risultato dell'algoritmo | `c0`, `20` |
| Due contatti realmente più vicini | `c0`, `a0` |

I bucket risultanti sono `00–7f: [10,20]`, `80–bf: [90,a0]`, `c0–ff: [c0]`.

### Correzione suggerita e accettazione

- Correggere l'ordine di visita a sinistra.
- Verificare separatamente che l'arresto anticipato selezioni davvero i `k` minimi XOR in tutte le configurazioni, anche con bucket parzialmente pieni o esclusioni.
- Convertire il controesempio in un test Rust.
- Confrontare `find_neighbors` con un oracolo che considera tutti i contatti eleggibili e seleziona i `k` minimi XOR. Controllare l'identità dei nodi selezionati, non solo l'ordinamento del risultato.
- Preservare la metrica completa a 160 bit e le esclusioni previste dal contratto.

## R04 — Rotazioni parziali e retry non idempotenti

**Riferimenti:** `src/network.rs`, `update_digest`, righe 673–711; `src/protocol.rs`, `rpc_update`; refresh tramite STORE.

[Commit locale dopo quorum](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/network.rs#L673-L711)

### Problema e scenario

Le repliche remote scrivono immediatamente; il coordinatore decide solo in seguito se aggiornare la copia locale.

1. A, B e C possiedono `V1`.
2. B e C applicano `V1 → V2`, autorizzato con la chiave di `V1`.
3. Le risposte UDP si perdono; A non raggiunge il quorum e conserva `V1`.
4. A ripete lo stesso UPDATE. B e C verificano ora la vecchia autorizzazione contro la chiave di `V2` e la rifiutano.
5. Il refresh tramite STORE incontra valori diversi e restituisce conflitto.

Il percorso GET locale può continuare a restituire la copia vecchia. Non basta mantenere la scrittura locale subordinata al quorum per ottenere recupero dopo una pubblicazione parziale.

### Correzione suggerita e accettazione

- Riconoscere gli UPDATE già applicati senza indebolire l'autorizzazione delle effettive modifiche.
- Definire una procedura autenticata per riallineare repliche arretrate.
- Chiarire il significato dell'esito quando l'operazione è stata applicata da alcuni nodi ma le risposte sono andate perse.
- Testare applicazione remota con perdita controllata delle risposte e successivo retry identico.
- Testare il recupero di una replica rimasta indietro, senza consentire sovrascritture non autorizzate o rollback.

## R05 — Copie integrali dello storage per contare i record

**Riferimenti:** `src/network.rs`, `stats`, righe 789–796, e task periodico alla riga 881; `src/storage.rs`, `iter_all`, righe 235–240.

[Statistiche](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/network.rs#L789-L796) · [Task periodico](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/network.rs#L881) · [Clonazione](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/storage.rs#L235-L240)

### Problema

`iter_all().len()` clona ogni chiave e ogni valore per ottenere soltanto un conteggio. Con circa 512 MiB di chiavi e valori attivi, può richiedere circa altri 512 MiB temporanei, oltre all'overhead. Il budget dello storage non include queste copie.

Il lavoro avviene sincronicamente sul runtime async. Anche altri percorsi di manutenzione e replica materializzano snapshot completi e vanno valutati rispetto al budget di memoria complessivo.

### Correzione suggerita e accettazione

- Contare i record senza clonare i payload, preservando la semantica di esclusione degli scaduti.
- Usare scansioni a blocchi o meccanismi equivalenti per manutenzione e replica.
- Verificare che le statistiche non allochino memoria proporzionale ai byte dei valori memorizzati.
- Misurare memoria di picco e latenza con dataset rappresentativi dell'hardware embedded; non usare le stime della review come benchmark.

## R06 — Discovery legata alla durata della replica

**Riferimenti:** `src/protocol.rs`, `schedule_welcome_if_new`, righe 298–325; `welcome_if_new`, righe 1051–1108. `WELCOME_CONCURRENCY = 1`.

[Ammissione](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/protocol.rs#L298-L325) · [Replica](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/protocol.rs#L1051-L1108)

### Problema

L'unico permesso disponibile resta occupato durante la scansione dello storage e tutta la replica di rete. Le scoperte degli altri peer vengono scartate prima dell'inserimento nel routing; il retry dipende da un successivo RPC.

Un destinatario lento o non responsivo, con molti record da replicare, può prolungare questa finestra per numerosi timeout.

### Correzione suggerita e accettazione

- Separare l'aggiornamento leggero dei contatti dalla replica costosa.
- Mantenere accodamento, deduplicazione e concorrenza della replica limitati.
- Testare che altri peer raggiungibili entrino nel routing mentre una replica verso un peer lento è ancora in corso.
- Verificare che la soluzione non crei code o task illimitati sotto churn.

## R07 — Arresto incompleto e attesa inutile per Leave

**Riferimenti:** `src/network.rs`, `listen` e `stop`, righe 235–296, task delle statistiche; `src/protocol.rs`, `call_leave_rpc`, righe 982–996, e `call`.

[Arresto](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/network.rs#L276-L296) · [Leave](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/protocol.rs#L982-L996)

### Problema

`stop()` interrompe solo refresh e salvataggio periodico. Ricevitore UDP, worker e task delle statistiche restano attivi e mantengono riferimenti al socket e allo storage. Il nodo può continuare a rispondere e la porta resta occupata.

Questo indebolisce il test di churn, che simula la partenza chiamando `stop()`.

Inoltre `Leave`, pur non prevedendo una risposta, passa attraverso `call()` e attende normalmente il timeout RPC di cinque secondi.

### Correzione suggerita e accettazione

- Gestire esplicitamente il ciclo di vita di tutti i task e rilasciare i riferimenti interni al protocollo/socket.
- Inviare `Leave` senza registrare una risposta attesa.
- Rendere l'arresto idempotente e aggiornare coerentemente lo stato esposto da `stats()`.
- Dopo `stop()`, verificare che il nodo non risponda più e che la porta sia riutilizzabile quando non esistono riferimenti esterni al socket/protocollo.
- Rafforzare il test di churn assicurando che il nodo uscente sia realmente inattivo.

## R08 — Head-of-line blocking nei worker UDP

**Riferimento:** `src/network.rs`, worker e receive loop, righe 235–264.

[Codice dello snapshot](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/network.rs#L235-L264)

### Problema

Ogni worker attende il completamento dell'intero `handle_datagram` prima di prelevare il datagramma successivo. Durante l'attesa di `spawn_blocking`, il thread Tokio è libero, ma quel worker non consuma la propria coda.

Un flusso di STORE può ritardare risposte RPC, PING e altri messaggi leggeri. Quando tutte le code sono piene, sospendere `recv_from` non applica backpressure al mittente UDP: il buffer del kernel può perdere pacchetti.

Il test da 40 bootstrap non verifica saturazione crittografica o isolamento delle risposte sotto carico misto. La dichiarazione di assenza di perdita di pacchetti non è garantita da questa architettura.

### Correzione suggerita e accettazione

- Separare il percorso delle risposte e dei messaggi leggeri dal lavoro crittografico, con ammissione limitata delle verifiche.
- Non sostituire il limite attuale con `spawn` illimitati.
- Misurare latenza delle risposte, timeout e perdite durante carico misto STORE/GET/PING, su un numero limitato di core.
- Aggiornare README per distinguere limiti delle code applicative e possibilità di perdita UDP nel kernel.

## R09 — Cache non invalidata quando cambia la chiave issuer

**Riferimenti:** `src/signature_cache.rs`, righe 28–45; `src/auth_handler.rs`, caricamento della chiave issuer; percorsi `verify_value` e `verify_for_key`.

[Chiave della cache](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/signature_cache.rs#L28-L45)

La cache include dominio e byte del record, ma non l'identità della chiave issuer. Dopo una rotazione di `issuer.bin`, un precedente esito può continuare a essere riutilizzato fino alla scadenza di un'ora. Il caricamento lazy del file non risolve il problema quando il percorso termina su un cache hit. Vale anche per gli esiti negativi divenuti obsoleti.

**Direzione:** invalidazione coerente al cambio di trust root oppure identificatore/generazione della chiave nel cache key. Rivalutare la gravità rispetto alla politica di rotazione issuer prevista.

**Accettazione:** con cache attiva, cambiare la chiave issuer deve rendere il risultato coerente con la nuova trust root, senza attendere il TTL della cache. Preservare la separazione issuer/self-signed.

## R10 — Contatti noti e ordine LRU

**Riferimenti:** `src/protocol.rs`, `schedule_welcome_if_new`, righe 301–304; `call_ping_node`; `src/routing.rs`, `KBucket::add_node`.

[Uscita anticipata](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/protocol.rs#L301-L304)

Il percorso di welcome esce immediatamente per un contatto già noto. I PONG dei nodi conosciuti non raggiungono quindi l'operazione che aggiorna l'ordine LRU, contrariamente al commento di `call_ping_node`.

**Direzione:** separare l'aggiornamento della liveness/LRU dalla discovery e replica dei nuovi contatti, rispettando i controlli sull'endpoint registrato.

**Accettazione:** un PONG valido dal contatto atteso deve aggiornare l'ordine LRU senza avviare una scansione dello storage. Non confondere questo aggiornamento con `last_updated` del bucket, che secondo AGENTS rappresenta l'attività di lookup.

## R11 — Cancellazione delle RPC e voci residue in pending

**Riferimento:** `src/protocol.rs`, `call`, righe 372–404.

[Codice dello snapshot](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/protocol.rs#L372-L404)

La voce in `pending` viene eliminata nei normali rami di completamento o timeout. Se il chiamante cancella la future prima che questi rami siano eseguiti e non arriva risposta, la voce resta nella mappa. Un timeout interno non continua a essere eseguito dopo che la future che lo contiene è stata cancellata.

**Direzione:** pulizia garantita alla cancellazione o un meccanismo equivalente di scadenza e ownership, senza introdurre ulteriore lavoro illimitato.

**Accettazione:** cancellare ripetutamente RPC verso un peer non responsivo e verificare che `pending` torni al livello iniziale entro un intervallo definito. Gestire anche eventuali risposte tardive.

## R12 — Limite dei frame incoerente

**Riferimenti:** `src/protocol.rs`, `send_frame` e `handle_datagram`, righe 423–435; `src/fragmentation.rs`, costanti e `encode_fragments`.

[Controllo in ricezione](https://github.com/fratrung/auth-kademlia-rs/blob/4eef5213c09dc67c1fa5bd189100582acd14b618/src/protocol.rs#L423-L435)

Il mittente ammette frame serializzati fino a `256 * 1024 = 262144` byte. Il ricevente verifica invece `total_fragments * 1400 <= 262144`.

| Dimensione frame serializzato | Frammenti | Ammesso dal mittente | Ammesso dal ricevente |
| --- | --- | --- | --- |
| 261800 byte | 187 | Sì | Sì |
| 261801 byte | 188 | Sì | No |
| 262144 byte | 188 | Sì | No |

L'intervallo **261801–262144 byte** è quindi ammesso in trasmissione ma scartato in ricezione. Le dimensioni si riferiscono al frame serializzato completo, non al solo valore del record.

**Direzione:** rendere coerenti i limiti considerando il frammento finale parziale e imponendo comunque un limite ai byte effettivamente accumulati. Non aumentare il budget di memoria senza revisione.

**Accettazione:** testare i tre confini indicati e il rifiuto di un messaggio realmente oltre il limite, preservando i limiti globali e per peer della ricomposizione.

## Protezioni da preservare

- Distanza XOR completa a 160 bit.
- Associazione DID–chiave controllata prima della cache.
- Domini distinti di verifica issuer e self-signed.
- STORE atomico e idempotente; conflitto per byte diversi sotto la stessa chiave.
- Budget dello storage e assenza di eviction dei record attivi per liberare capacità.
- Verifica dell'endpoint e del tipo delle risposte RPC.
- Limiti alla ricomposizione dei frammenti.

Il rifiuto di una sola copia valida con `alpha = 3` è una scelta dichiarata del quorum remoto, non un difetto aggiuntivo dimostrato da questa review. Analogamente, la firma valida di un record non dimostra da sola che sia la versione più recente.

## Sequenza di lavoro suggerita

1. Rivalidare tutti i rilievi sul commit corrente e verificare gli strumenti di build disponibili.
2. Affrontare R01 e R04 insieme per definire aggiornamenti atomici, retry e recupero.
3. Definire la protezione dal replay di R02 e la gestione della trust root di R09, rispettando compatibilità e istruzioni del progetto.
4. Correggere R03 con test contro un oracolo XOR.
5. Correggere R05 e R06 per ridurre memoria temporanea e dipendenza della discovery dalla replica.
6. Correggere R07 prima di attribuire affidabilità ai risultati dei test di churn e resilienza.
7. Verificare R08 con carico misto; correggere R10, R11 e R12 con test mirati.
8. Eseguire i test del progetto e i test di regressione pertinenti. Riportare separatamente eventuali verifiche dei binding Python e benchmark sull'hardware target.

## Formato del rapporto finale dell'agente

Per ogni ID riporta:

- Stato: confermato / corretto / già risolto / non riprodotto / decisione necessaria.
- Evidenza sul commit effettivamente esaminato.
- File modificati e comportamento risultante, se sono state richieste correzioni.
- Test e comandi realmente eseguiti, con esito.
- Limiti residui e impatto su wire format, API, quorum o compatibilità.

Non dichiarare assenza di colli di bottiglia, correttezza completa, superamento dei test o sicurezza del protocollo sulla sola base di questa review statica.
