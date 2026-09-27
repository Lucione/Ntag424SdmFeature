# Baseline di Contesto Architetturale e di Sicurezza
**Progetto:** Ntag424SdmFeature (`de.androidcrypto.ntag424sdmfeature`)  
**Data Documento:** Maggio 2024 / Corrente  
**Autore:** Lead Mobile Architect & NFC Cryptographic Security Expert  
**Target Hardware:** NXP NTAG 424 DNA / NTAG 424 DNA TagTamper (NT4H2421Gx / NT4H2421Tx)

---

## 1. Panoramica e Architettura del Progetto

### 1.1 Inquadramento e Moduli
Il progetto è una soluzione Android nativa sviluppata in Java (compatibile con Java 8 / `compileSdk 34`, `minSdk 21`, `targetSdk 34`), strutturata attorno a un unico modulo applicativo Gradle (`:app`).

Il progetto non fa uso di librerie esterne di terze parti per le operazioni di crittografia o comunicazione NFC, integrando direttamente all'interno del sorgente un SDK di basso livello per la gestione del chip **NXP NTAG 424 DNA**.

```
Ntag424_ORG/
├── app/
│   ├── build.gradle (namespace: de.androidcrypto.ntag424sdmfeature)
│   └── src/main/
│       ├── AndroidManifest.xml
│       └── java/
│           ├── de/androidcrypto/ntag424sdmfeature/   # Layer UI & Workflow Application
│           └── net/bplearning/ntag424/              # Layer Core Protocol, Crypto & Commands
└── docs/                                           # Datasheet NXP, specifiche ISO/IEC e documentazione
```

### 1.2 Architettura del Codice e Package

Il sorgente è organizzato in due namespace principali con responsabilità nettamente separate:

1. **`de.androidcrypto.ntag424sdmfeature` (UI & Application Logic Layer)**
   - **Activity Principali:** Contiene 11 `AppCompatActivity` dedicate all'interazione con l'utente e all'orchestrazione dei singoli casi d'uso (configurazione NDEF, cifratura SUN, diversificazione chiavi, ripristino stato di fabbrica).
   - **Helper & Constants:**
     - `Constants.java`: Definisce le chiavi AES predefinite di fabbrica, le chiavi applicative di test, il Master Key per la diversificazione e i vettori di Capability Container (CC).
     - `Utils.java`: Fornisce primitive utility per la conversione esadecimale (`bytesToHex`, `hexStringToByteArray`), manipolazione di byte array e parsing dei record NDEF.
     - `DnacFileSettingsDumper.java`: Utility per l'ispezione e il dumping formattato della struttura `FileSettings` e `SDMSettings` in stringhe leggibili.

2. **`net.bplearning.ntag424` (NTAG 424 DNA Protocol SDK)**
   - **`net.bplearning.ntag424`**:
     - `DnaCommunicator`: Orchestratore centrale della sessione NFC. Gestisce l'invio dei frame APDU, il contatore dei comandi (`commandCounter`), il Transaction Identifier (`TI`), l'autenticazione attiva e il logging.
     - `CommandResult`: Inserisce e modella i byte di risposta e gli status byte (SW1, SW2 / Status1, Status2 NXP) dei comandi.
     - `CommunicationMode`: Enum per definire il livello di protezione della comunicazione (`PLAIN`, `MAC`, `FULL`).
   - **`.command`**: Implementazione dei singoli comandi NXP native / ISO 7816-4 (`ChangeFileSettings`, `ChangeKey`, `GetFileSettings`, `GetCardUid`, `GetReadCounter`, `ReadData`, `WriteData`, `IsoSelectFile`, `SetCapabilities`, `SetFailedAuthCounterSettings`, `SetPICCConfiguration`).
   - **`.encryptionmode`**: Gestione del canale di cifratura di sessione.
     - `EncryptionMode`: Interfaccia astratta per la cifratura/decifratura dati e generazione MAC di sessione.
     - `AESEncryptionMode`: Implementazione dello schema di autenticazione EV2 (NXP LRP/EV2 Secure Channel).
     - `LRPEncryptionMode`: Implementazione dello schema Leakage-Resilient Primitive (LRP).
   - **`.sdm`**: Engine per la gestione del Secure Dynamic Messaging (SUN).
     - `NdefTemplateMaster`: Parser e generatore di template NDEF dinamici con ricalcolo degli offset di memoria.
     - `PiccData`: Engine di decodifica e validazione del blocco cifrato `picc_data` e del codice `cmac`.
     - `SDMSettings`: Data class contenente la configurazione delle opzioni e dei permessi SDM/SUN.
   - **`.lrp`**: Implementazione dell'algoritmo di cifratura LRP (`LRPCipher`, `LRPCMAC`, `LRPMultiCipher`).
   - **`.aes`**: Wrapper per l'esecuzione dell'algoritmo AES-CMAC (`AESCMAC`).
   - **`.card`**: Data class per la modellazione delle chiavi (`KeyInfo`, `KeySet`).
   - **`.constants`**: Definizione di costanti di sistema (`Ntag424`, `Permissions`, `Crypto`, `Ndef`).
   - **`.util`**: Operazioni matematiche su bit/byte e primitive crittografiche (`ByteUtil`, `BitUtil`, `Crypto`).

### 1.3 Pattern di Concorrenza e Ciclo di Vita NFC
- Le interazioni con il lettore NFC non bloccano il thread principale dell'UI (UI Thread).
- Le Activity implementano `NfcAdapter.ReaderCallback`. Il metodo `onTagDiscovered(Tag tag)` viene invocato dal sistema operativo su un thread di I/O secondario (`Binder thread`).
- Le operazioni bloccanti sui comandi APDU vengono eseguite all'interno di un `Thread` dedicato (`runWorker()`).
- Gli aggiornamenti dell'interfaccia utente vengono riaffidati all'UI Thread tramite l'invocazione di `runOnUiThread(...)`.

---

## 2. Gestione e Configurazione NFC

### 2.1 Integrazione Android NFC ReaderMode
L'applicazione forza l'uso della modalità **ReaderMode** esclusiva per evitare conflitti con la gestione NDEF automatica di Android.

Nei metodi `onResume()` delle Activity, il ciclo di vita NFC viene registrato tramite:
```java
Bundle options = new Bundle();
options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

mNfcAdapter.enableReaderMode(
    this,
    this,
    NfcAdapter.FLAG_READER_NFC_A |
    NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK |
    NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
    options
);
```

**Significato dei Flag:**
- `FLAG_READER_NFC_A`: Limita l'aggancio ai soli tag basati su tecnologia ISO/IEC 14443-4 Type A.
- `FLAG_READER_SKIP_NDEF_CHECK`: Impedisce al sistema Android di eseguire il parsing NDEF automatico in sottofondo, garantendo il controllo diretto dei comandi APDU.
- `FLAG_READER_NO_PLATFORM_SOUNDS`: Disattiva il feedback sonoro standard di sistema.
- `EXTRA_READER_PRESENCE_CHECK_DELAY` (`250 ms`): Introduce una pausa controllata per stabiizzare la comunicazione su firmware NFC con polling aggressivo.

### 2.2 Tecnologie ISO-DEP e Trasmisione Frame APDU
- La connessione diretta avviene tramite l'astrazione `IsoDep.get(tag)`.
- Il canale fisico viene aperto con `isoDep.connect()`.
- L'astrazione del trasporto viene passata a `DnaCommunicator` tramite una lambda/functional interface:
  ```java
  dnaC.setTransceiver((bytesToSend) -> isoDep.transceive(bytesToSend));
  ```

### 2.3 Struttura dei Comandi APDU (ISO 7816-4 Wrapped Native Commands)
`DnaCommunicator` gestisce l'incapsulamento dei comandi NXP Native all'interno di frame ISO/IEC 7816-4 APDU:

1. **Inizio Comunicazione / Selezione DF (`beginCommunication`)**:
   Invia un comando `IsoSelectFile` per selezionare l'Application DF dell'NTAG 424 DNA (`DF_FILE_ID = {0xE1, 0x04}` oppure `0x3F00` / `0xD2760000850101`).
   
2. **Costruzione Frame ISO (`isoCommand`)**:
   `[CLA] [INS] [P1] [P2] [Lc] [DATA] [Le]`
   - `CLA`: `0x00` per comandi ISO standard o `0x90` per comandi NXP Native wrappati.
   - `P1`, `P2`: Parametri aggiuntivi (es. `0x00, 0x00`).
   - `Lc`: Lunghezza del payload dati.
   - `Le`: Lunghezza attesa della risposta (`0x00` per la totalità).

3. **Comando NXP Native Wrappato (`nxpNativeCommand`)**:
   `0x90 [CMD] 0x00 0x00 [Lc] [HDR + DATA + MAC] 0x00`
   Invia il codice di comando NXP (es. `0x71` per EV2 First Auth, `0xF5` per GetFileSettings, `0x5F` per ChangeFileSettings, `0x8D` per WriteData, `0xAD` per ReadData).

---

## 3. Sicurezza, Crittografia e Autenticazione

### 3.1 Architettura delle Chiavi dell'NTAG 424 DNA
L'NTAG 424 DNA supporta **5 chiavi d'applicazione AES-128** (Key 0, Key 1, Key 2, Key 3, Key 4).
Ogni chiave è costituita da 16 byte (128 bit).

```
+-------+----------------------------------+-------------------------------------------------------------+
| Key # | Ruolo Predefinito nell'App       | Valore di Default / Custom                                  |
+-------+----------------------------------+-------------------------------------------------------------+
| Key 0 | App Master Key                   | 0x00000000000000000000000000000000 (Factory Default)         |
| Key 1 | App Key 1                        | 0xA1000000000000000000000000000000 (Custom Key 1)           |
| Key 2 | SUN Meta / File Read Key         | 0xA2000000000000000000000000000000 (Custom Key 2 - SUN Default)|
| Key 3 | File Encrypted Data Key          | 0xA3000000000000000000000000000000 (Custom Key 3)           |
| Key 4 | MAC Validation / Diversified Key | 0xA4000000000000000000000000000000 (Custom Key 4)           |
+-------+----------------------------------+-------------------------------------------------------------+
```

### 3.2 Key Diversification (AN10922)
L'app implementa la diversificazione delle chiavi basata su specifica NXP AN10922 nel metodo `KeySet.generateKeySetFromMasterKey(...)` e `Crypto.diversifyKey(...)`:
- **Master Application Key**: `0xA9000000000000000000000000000000`
- **System Identifier**: `0x666F6F` ("foo")
- **Input per la Diversificazione**: `[Header 0x01/0x02] + [UID Tag (7 byte)] + [System ID (3 byte)] + [Key No (1 byte)]`
- **Algoritmo**: Derivazione AES-CMAC a 128-bit. Produce una chiave unica per ogni singolo chip fisico mantenendo memorizzata sul server la sola Master Key.

### 3.3 Protocollo di Autenticazione EV2 First Auth (`AESEncryptionMode`)
Il canale sicuro EV2 viene stabilito tramite handshake a due fasi (`AESEncryptionMode.authenticateEV2`):

```
Smartphone (PCD)                                          Tag NTAG 424 DNA (PICC)
      |                                                             |
      | ------ CMD 0x71 (AuthenticateEV2First, KeyNum) ----------> |
      | <----- Status 0x90 0xAF + Encrypted RndB (16 bytes) ------- |
      |                                                             |
   [ Decifra RndB con K_Auth ]                                      |
   [ Genera RndA ]                                                  |
   [ Ruota RndB -> RndB' ]                                          |
   [ Cifra (RndA + RndB') ]                                         |
      |                                                             |
      | ------ CMD 0xAF + Encrypted (RndA + RndB') ----------------> |
      | <----- Status 0x90 0x00 + Encrypted (TI + RndA' + Caps) ---- |
      |                                                             |
   [ Decifra e verifica RndA' ]                                     |
   [ Salva Transaction Identifier TI (4 bytes) ]                    |
   [ Deriva KSesAuthENC e KSesAuthMAC ]                             |
   [ Reset CommandCounter = 0 ]                                     |
```

#### Derivazione delle Chiavi di Sessione EV2:
- **`KSesAuthENC`**: Generata eseguendo AES-CMAC con la chiave master `K_Auth` sul vettore di sessione derivato con prefisso `[0xA5, 0x5A]`.
- **`KSesAuthMAC`**: Generata eseguendo AES-CMAC con la chiave master `K_Auth` sul vettore di sessione derivato con prefisso `[0x5A, 0xA5]`.

### 3.4 Modalità di Protezione dei Comandi
Una volta stabilita la sessione cifrata, `DnaCommunicator` supporta 3 modalità di comunicazione (`CommunicationMode`):

1. **`PLAIN`**: Il comando viene inviato in chiaro. Incrementa il `commandCounter`.
2. **`MAC` (`nxpMacCommand`)**:
   - Calcola un codice CMAC sui dati in uscita: `CMAC(KSesAuthMAC, CMD + CmdCtr + TI + Header + Data)`.
   - Il CMAC viene troncato agli 8 byte significativi (Shortened CMAC) ed allegato al comando.
   - Verifica obbligatoriamente il MAC restituito dalla risposta del tag: `CMAC(KSesAuthMAC, SW2 + CmdCtr + TI + ResponseData)`.
   - Incrementa il `commandCounter`.
3. **`FULL` (`nxpEncryptedCommand`)**:
   - Cifra il payload dati utilizzando **AES-128-CBC** senza padding.
   - L'IV per la cifratura viene calcolato cifrando con `KSesAuthENC` il blocco `[0xA5, 0x5A, TI(4 byte), CmdCtr(2 byte LSB), 0x00 * 8]`.
   - Applica il calcolo del MAC di sessione sull'intero pacchetto cifrato.
   - Decifra i dati ricevuti in risposta con IV dinamico inverso `[0x5A, 0xA5, TI(4 byte), CmdCtr(2 byte LSB), 0x00 * 8]`.

### 3.5 Operazione di Modifica Chiave (`ChangeKey`)
Implementata in `ChangeKey.java` (Comando `0xC4`):
- È obbligatorio essere autenticati con **Key 0**.
- **Modifica di Key 0**: Invia `[NewKey (16 byte)] + [KeyVersion (1 byte)]` cifrati in sessione FULL. Riavvia la sessione di autenticazione con `restartSession()`.
- **Modifica di Key 1..4**: Invia `[XOR(OldKey, NewKey) (16 byte)] + [KeyVersion (1 byte)] + [JamCRC32(NewKey) (4 byte)]` cifrati in sessione FULL.

---

## 4. Implementazione del Protocollo SUN (Secure Unique NFC)

### 4.1 Meccanismo SDM (Secure Dynamic Messaging)
Il protocollo **SUN / SDM** è una funzionalità hardware dell'NTAG 424 DNA che consente al chip di modificare dinamicamente il contenuto del record NDEF durante la lettura contactless, inserendo valori aggiornati per l'UID, il contatore di lettura e un codice di verifica crittografico (CMAC).

### 4.2 Template URL e Placeholder (`NdefTemplateMaster`)
La classe **[NdefTemplateMaster](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/net/bplearning/ntag424/sdm/NdefTemplateMaster.java)** converte un URL con segnaposto in una struttura di byte NDEF valida e determina in modo automatico gli offset hardware da salvare nelle `SDMSettings`:

```
Template Input:
https://logicarts.altervista.org/verify.php?uid={UID}&picc_data={PICC}&cmac={MAC}

Output generato sul Tag (Record NDEF):
https://logicarts.altervista.org/verify.php?uid=**************&picc_data=********************************&cmac=****************
```

#### Mapping dei Placeholder e Offset:
- **`{UID}`**: Riserva 14 caratteri ASCII (`*`). Imposta `sdmOptionUid = true` e determina `sdmUidOffset`.
- **`{COUNTER}`**: Riserva 6 caratteri ASCII (`*`). Imposta `sdmOptionReadCounter = true` e determina `sdmReadCounterOffset`.
- **`{PICC}`**: Riserva 32 o 48 caratteri ASCII (`*`). Determina `sdmPiccDataOffset`. Utilizzato quando `sdmMetaReadPerm` è associato a una chiave (es. Key 2).
- **`{MAC}`**: Riserva 16 caratteri ASCII (`*`). Determina `sdmMacOffset`.
- **`{FILE}`**: Riserva lo spazio per dati file cifrati (multipli di 16 byte). Determina `sdmEncOffset` e `sdmEncLength`.

### 4.3 Struttura del Blocco Cifrato `PICCData` (`PiccData.java`)
Quando `sdmMetaReadPerm` è impostato su una chiave diversa da `ACCESS_EVERYONE` (es. `ACCESS_KEY2`), il tag genera un blocco `picc_data` cifrato di 16 byte (32 cifre esadecimali ASCII).

#### Decodifica del `PICCData` (`PiccData.decodeFromEncryptedBytes`):
1. **Decifratura**: Il blocco di 16 byte viene decifrato tramite **AES-128-CBC** con la chiave `MetaRead` (es. Key 2) e **IV = 16 byte di `0x00`**.
2. **Struttura Byte Decifrati (16 Byte)**:
   - `Byte 0`: Header dei Flag (`Bit 7` = Presenza UID, `Bit 6` = Presenza Read Counter).
   - `Byte 1..7`: **UID del tag** (7 byte).
   - `Byte 8..10`: **Read Counter** (3 byte, intero in formato LSB / Little Endian).
   - `Byte 11..15`: Padding / byte di riempimento.

### 4.4 Calcolo e Verifica del `CMAC`
Per verificare l'autenticità del messaggio SUN ricevuto nell'URL:

1. **Derivazione della Session Key SDM**:
   Con la chiave `sdmFileReadPerm` (es. Key 2) e l'UID e Read Counter estratti, si genera la `KSesSDMMAC`:
   - `SV = [0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80] + UID[7 byte] + ReadCounter[3 byte LSB]`
   - `KSesSDMMAC = AES-CMAC(K_FileRead, SV)`
2. **Calcolo MAC**:
   Si esegue l'AES-CMAC con `KSesSDMMAC` sul contenuto specificato da `sdmMacInputOffset`.
3. **Troncamento**:
   Si estrae il MAC troncato a 8 byte (16 caratteri HEX). Se corrisponde al valore `cmac` dell'URL, il messaggio è autentico.

---

## 5. Flussi di I/O Dati

### 5.1 Mappatura della Memoria dell'NTAG 424 DNA
L'NTAG 424 DNA organizza la propria memoria interna attorno a file logici predefiniti identificati da un File Number (0x01, 0x02, 0x03):

```
+---------+------------------------------+--------------------+-----------------------------------------------------+
| File ID | Nome File / Descrizione      | Dimensione Default | Permessi Tipici SUN / SDM                           |
+---------+------------------------------+--------------------+-----------------------------------------------------+
| File 01 | Capability Container (CC)    | 32 Byte            | Read: Free (0xE), Write: Key 0 / Disabled           |
| File 02 | NDEF Message File            | 256 Byte           | Read: Free (0xE) / Key 2, Write: Key 2 / Key 0      |
| File 03 | Protected Data File          | Configurabile      | Read: Key 3 / Key 4, Write: Key 3 / Key 4           |
+---------+------------------------------+--------------------+-----------------------------------------------------+
```

### 5.2 Struttura `FileSettings` (`net.bplearning.ntag424.command.FileSettings`)
Rappresenta la configurazione di un file letto tramite `GetFileSettings` (CMD `0xF5`) o scritta tramite `ChangeFileSettings` (CMD `0x5F`).

#### Matrice dei Permessi (Nibble Nibble Encoding):
- `readPerm` (4 bit): Permesso di lettura.
- `writePerm` (4 bit): Permesso di scrittura.
- `readWritePerm` (4 bit): Permesso di lettura e scrittura combinato.
- `changePerm` (4 bit): Permesso di modifica delle impostazioni del file (CAR - Change Access Rights).

Valori dei Permessi (`Permissions.java`):
- `0x0` .. `0x4`: Richiede autenticazione con la rispettiva Key 0 .. Key 4.
- `0xE` (`ACCESS_EVERYONE`): Lettura/Scrittura libera senza autenticazione.
- `0xF` (`ACCESS_NONE`): Accesso disabilitato/bloccato.

### 5.3 Operazioni di Scrittura e Lettura Dati (`WriteData` & `ReadData`)
- **`ReadData` (CMD `0xAD`)**: Legge un blocco di dati specificando l'offset di memoria e la lunghezza. Rispetta la modalità di comunicazione descritta nelle `FileSettings` (`PLAIN`, `MAC`, `FULL`).
- **`WriteData` (CMD `0x8D`)**: Scrive dati nel file target. Nel flusso SUN, viene utilizzato per scrivere l'URL formattato nel File 02 prima dell'abilitazione dei flag SDM.

---

## 6. Mappa dei Componenti Chiave per il Developer

### 6.1 UI Layer (`de.androidcrypto.ntag424sdmfeature`)

- **[MainActivity.java](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/de/androidcrypto/ntag424sdmfeature/MainActivity.java)**
  - *Scopo*: Dashboard principale dell'applicazione per la selezione del caso d'uso.

- **[PrepareActivity.java](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/de/androidcrypto/ntag424sdmfeature/PrepareActivity.java)**
  - *Scopo*: Inizializzazione di base del tag (scrittura Capability Container nel File 01 e template NDEF base nel File 02).

- **[PlaintextSunActivity.java](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/de/androidcrypto/ntag424sdmfeature/PlaintextSunActivity.java)**
  - *Scopo*: Configurazione del messaggio SUN in testo chiaro (UID e/o Read Counter non cifrati + CMAC).

- **[EncryptedSunActivity.java](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/de/androidcrypto/ntag424sdmfeature/EncryptedSunActivity.java)**
  - *Scopo*: Configurazione del messaggio SUN cifrato (PICCData cifrato con Key 2 + CMAC).

- **[EncryptedFileSunActivity.java](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/de/androidcrypto/ntag424sdmfeature/EncryptedFileSunActivity.java)**
  - *Scopo*: Configurazione avanzata SUN con PICCData cifrato e sezione file data cifrata.

- **[EncryptedFileSunCustomKeysActivity.java](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/de/androidcrypto/ntag424sdmfeature/EncryptedFileSunCustomKeysActivity.java)**
  - *Scopo*: Configurazione SUN con utilizzo di chiavi applicative personalizzate (Key 1..4 != default 0x00).

- **[EncryptedFileSunDiversifiedKeysActivity.java](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/de/androidcrypto/ntag424sdmfeature/EncryptedFileSunDiversifiedKeysActivity.java)**
  - *Scopo*: Configurazione SUN con diversificazione dinamica delle chiavi basata su UID del tag e Master Key.

- **[UnsetActivity.java](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/de/androidcrypto/ntag424sdmfeature/UnsetActivity.java)**
  - *Scopo*: Ripristino delle condizioni di fabbrica del tag (reset chiavi a 0x00, disabilitazione SDM, ripristino CC e permessi liberi).

- **[NdefReaderActivity.java](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/de/androidcrypto/ntag424sdmfeature/NdefReaderActivity.java)**
  - *Scopo*: Lettura e decodifica di un messaggio NDEF SUN direttamente nell'app con decifratura locale di PICCData e validazione CMAC.

- **[TagOverviewActivity.java](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/de/androidcrypto/ntag424sdmfeature/TagOverviewActivity.java)**
  - *Scopo*: Ispezione completa del tag (lettura UID, versione delle chiavi, configurazione permessi e FileSettings dei file 01 e 02).

---

### 6.2 Core SDK Layer (`net.bplearning.ntag424`)

- **[DnaCommunicator](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/net/bplearning/ntag424/DnaCommunicator.java)**
  - `public void beginCommunication()`: Seleziona l'applicazione NTAG 424 DNA.
  - `public CommandResult isoCommand(...)`: Esegue un comando APDU ISO 7816-4.
  - `public CommandResult nxpMacCommand(...)`: Esegue un comando protetto da MAC di sessione.
  - `public CommandResult nxpEncryptedCommand(...)`: Esegue un comando protetto da cifratura FULL e MAC di sessione.

- **[AESEncryptionMode](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/net/bplearning/ntag424/encryptionmode/AESEncryptionMode.java)**
  - `public static boolean authenticateEV2(DnaCommunicator comm, int keyNum, byte[] keyData)`: Esegue il flusso di autenticazione EV2 First Auth.
  - `public byte[] encryptData(byte[] message)`: Cifra un payload dati con AES-128-CBC dinamico.
  - `public byte[] decryptData(byte[] message)`: Decifra un payload dati.

- **[NdefTemplateMaster](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/net/bplearning/ntag424/sdm/NdefTemplateMaster.java)**
  - `public byte[] generateNdefTemplateFromUrlString(String urlString, SDMSettings sdmDefaults)`: Analizza un URL con placeholder, calcola gli offset hardware e compila le `SDMSettings`.

- **[PiccData](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/net/bplearning/ntag424/sdm/PiccData.java)**
  - `public static PiccData decodeFromEncryptedBytes(byte[] encryptedData, byte[] key, boolean usesLrp)`: Decifra il blocco `picc_data` ed ne estrae UID e Read Counter.
  - `public static PiccData decodeAndVerifyMac(...)`: Decodifica e verifica la validità del CMAC ricevuto.

- **[FileSettings](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/net/bplearning/ntag424/command/FileSettings.java)**
  - `public static FileSettings decodeFromData(byte[] data)`: Decodifica i byte restituiti da GetFileSettings.
  - `public byte[] encodeToData()`: Codifica la struttura impostazioni in byte array per il comando ChangeFileSettings.

- **[ChangeKey](file:///D:/Sviluppo/Android/Ntag424_ORG/app/src/main/java/net/bplearning/ntag424/command/ChangeKey.java)**
  - `public static void run(DnaCommunicator comm, int keyNum, byte[] oldKey, byte[] newKey, int keyVersion)`: Cambia il valore e la versione di una chiave AES.
