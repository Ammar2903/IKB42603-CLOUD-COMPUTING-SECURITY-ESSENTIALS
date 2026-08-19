# Lab 3: Encryption and Key Management

* **Course Code:** IKB42603 Cloud Computing Security Essentials
* **Student Name:** Sharif Ammar Izzuddin Bin Sharif Yusri
* **Student ID:** 52215124783
* **Lecturer:** Madam Nor Adani Kamal Mohamad Nasir

---

## Executive Summary
This laboratory exercise provides hands-on implementation and technical verification of cloud data protection mechanisms, focusing on encryption at rest, encryption in transit, centralized key management, envelope encryption, cryptographic erasure, and record integrity. Executed within a Linux/Kali VM environment using OpenSSL and LocalStack to emulate AWS Key Management Service (KMS), the lab demonstrates foundational cryptographic primitives and enterprise-grade key management patterns.

## Key Learning Objectives & Technical Scope
* Symmetric & Asymmetric Cryptography: Practical implementation of AES-256-CBC for confidential data at rest and RSA-2048 for key transport and digital signatures.
* Data in Transit Protection: Deployment of an NGINX web server instance containerized via Docker to enforce Transport Layer Security (TLS/HTTPS).
* KMS & Envelope Encryption: Implementation of AWS KMS Customer Master Keys (CMKs) to wrap local Data Encryption Keys (DEKs) for scalable data protection.
* Per-Tenant Isolation & Cryptographic Erasure: Simulation of multi-tenant cryptographic boundaries and provable cloud data deletion through key disablement and deletion scheduling.
* Data Integrity & Tamper-Evidence: Verification of data alteration using SHA-256 cryptographic hashing and construction of an append-only, tamper-evident hash-chained log structure.

## Lab Summary & Architecture Overview

| Phase / Session | Focus Area | Key Tools & Protocols | Primary Output / Verification | 
| :--- | :--- | :--- | :--- | 
| Session A (Week 5) | Encryption Fundamentals   | OpenSSL, Docker, NGINX, TLS 1.2/1.3 | AES ciphertext match, RSA digital signature validation, HTTPS connection |
| Session B (Week 6) | Key Management & Integrity | LocalStack (AWS KMS), SHA-256 | Envelope encryption cycle, failed decrypt post-erasure, tamper-evident hash chain   |

---

## Session A (Week 5) — Encryption Fundamentals

## Task 1 — Symmetric Encryption (Data at Rest)

## Objective
To create a sensitive file containing confidential patient records and protect it at rest using symmetric encryption (AES-256-CBC) via OpenSSL. This task demonstrates both encryption and decryption using a single shared secret key, as well as verifying data integrity post-decryption.

* Commands Executed
```yaml
# 1. Create a sample sensitive file
echo 'Patient: Ahmad, Diagnosis: confidential' > record.txt

# 2. Encrypt the file using AES-256-CBC with PBKDF2 key derivation and salt
openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc

# 3. Inspect the encrypted file (verify it is unreadable binary ciphertext)
cat record.enc

# 4. Decrypt the file and compare with the original file
openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt
diff record.txt record.dec.txt && echo 'MATCH: decryption successful'
```
* Screenshot / Evidence
<img width="657" height="297" alt="Task1" src="https://github.com/user-attachments/assets/f81fd742-bcf4-474c-bacf-6bad53ae24a2" />

## Technical Explanation & Analysis
  * Sensitive Data Creation: A plain text record `record.txt` was generated representing data at rest.
  * AES-256-CBC Encryption: OpenSSL encrypted the file using the AES-256-CBC algorithm.
     * The `-pbkdf2` flag enforces the use of Password-Based Key Derivation Function 2, mitigating brute-force attacks against the passphrase.
     * The `-salt` parameter introduces random data prior to hashing, preventing rainbow table attacks.
  * Ciphertext Verification: Executing `cat record.enc` returned non-human-readable binary noise, proving that confidentiality was maintained at rest.
  * Decryption & Integrity Match: The file was successfully decrypted using the same shared passphrase. The `diff` command returned no differences between `record.txt` and `record.dec.txt`, triggering the output `MATCH: decryption successful`.

---

## Task 2 — Asymmetric Encryption & Digital Signatures

## Objective
To generate a 2048-bit RSA key pair and demonstrate asymmetric cryptography principles via OpenSSL. This task covers encrypting confidential data with a public key, decrypting it with a private key, and generating digital signatures to guarantee data origin authenticity and non-repudiation.

* Commands Executed
```yaml
# 1. Generate a 2048-bit RSA private key and extract the corresponding public key
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# 2. Encrypt the plaintext using the PUBLIC key, then decrypt using the PRIVATE key
openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt

# 3. Digitally sign the record using the PRIVATE key and verify with the PUBLIC key
openssl dgst -sha256 -sign private.pem -out record.sig record.txt
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

* Screenshot / Evidence
<img width="728" height="218" alt="Task2" src="https://github.com/user-attachments/assets/ed5a2f1d-376e-44a9-8c9a-eeaeb8c1490f" />

## Technical Explanation & Analysis
* Key Pair Generation: A 2048-bit RSA private key (`private.pem`) was generated, from which the public key (`public.pem`) was derived. The public key can be freely distributed, while the private key must remain strictly protected.
* Asymmetric Confidentiality (Public Key Encryption):
  * Data in `record.txt` was encrypted using `public.pem` (`record.rsa`).
  * Decryption was exclusively possible using `private.pem` (`record.rsa.txt`). This eliminates the key-distribution vulnerability inherent in pure symmetric encryption because the sender never needs to handle the private decryption key.
* Authenticity & Integrity (Digital Signing):
  * The roles were reversed for digital signatures: `record.txt` was signed using the sender's private key (`private.pem`).
  * The signature `record.sig` was verified using the sender's public key (`public.pem`), yielding the output `Verified OK`.
  * This proves two critical security properties: Integrity (the file content was not altered) and Authenticity/Non-repudiation (only the holder of the matching private key could have produced the signature).

---

## Task 3 — Encryption in Transit (TLS)

## Objective
To generate an X.509 self-signed SSL/TLS certificate and configure an NGINX web server container via Docker to serve confidential records securely over HTTPS. This task demonstrates data-in-transit protection, ensuring intercepted network traffic cannot be read in plaintext.

* Commands Executed
```yaml
# 1. Generate a self-signed X.509 certificate and private key valid for 7 days
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 7 -nodes -subj '/CN=localhost'

# 2. Deploy an NGINX container mapping port 8443 to port 443 with TLS certificates mounted
docker run --rm -d --name tls -p 8443:443 \
  -v $(pwd)/cert.pem:/etc/nginx/cert.pem -v $(pwd)/key.pem:/etc/nginx/key.pem \
  -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt nginx

# 3. Retrieve the record securely over HTTPS (-k bypasses self-signed CA verification)
curl -k https://localhost:8443/record.txt
```

* Screenshots / Evidence
<img width="941" height="621" alt="Task3_1" src="https://github.com/user-attachments/assets/5492bdc4-cc2d-4aff-aa5f-8eab44babffd" />
<img width="450" height="72" alt="Task3_2" src="https://github.com/user-attachments/assets/fb38e248-1884-4802-b7bb-dcc37fe23a74" />

## Technical Explanation & Analysis
* Certificate Generation: A 2048-bit RSA private key (`key.pem`) and an X.509 self-signed certificate (`cert.pem`) were generated using OpenSSL. The `-nodes` flag prevented passphrase protection on the private key, allowing the NGINX container to start automatically without interactive prompt intervention.
* HTTPS Container Deployment: An NGINX container was spawned using Docker with host port `8443` bound to container SSL port `443`. The certificate, key, and sensitive `record.txt` file were volume-mounted directly into the container environment.
* Encrypted Channel Verification:
  * Executing `curl -k https://localhost:8443/record.txt` successfully retrieved `Patient: Ahmad, Diagnosis: confidential` over an encrypted TLS connection.
  * The `-k` flag instructed `curl` to accept the self-signed certificate without failing on CA chain validation.
* Security Context: Unlike unencrypted HTTP (port 80) where traffic flows in cleartext and is vulnerable to packet sniffing or man-in-the-middle eavesdropping, TLS encrypts the payload during transit across the network boundary.

---

## Session B (Week 6) — Key Management, Envelope Encryption & Erasure
Start LocalStack if it is not running (see Lab 1). Set EP='--endpoint-url=http://localhost:4566'.

## Task 4 — Create and Use a KMS Master Key

## Objective
To provision a Customer Master Key (CMK) within LocalStack AWS KMS and demonstrate direct KMS encryption on small data payloads. This task introduces centralized, cloud-managed key administration where cryptographic keys reside within secure service boundaries.

* Commands Executed
```yaml
# 1. Set LocalStack endpoint parameter
EP='--endpoint-url=http://localhost:4566'

# 2. Create a Customer Master Key (CMK) for Tenant A
aws $EP kms create-key --description 'CCSE tenant-A master key'

# 3. Store the returned KeyId into an environment variable
KEY_A="PASTE_KEYID"

# 4. Encrypt a small secret payload directly using KMS
aws $EP kms encrypt --key-id $KEY_A --plaintext "$(echo -n 'hello' | base64)" \
  --query CiphertextBlob --output text
```

* Screenshot / Evidence
<img width="942" height="507" alt="Task4" src="https://github.com/user-attachments/assets/525e5691-7c9c-4ee8-abd0-6628eee42332" />

## Technical Explanation & Analysis
* KMS CMK Provisioning:
  * The `aws kms create-key` command created a Customer Master Key (CMK) managed by LocalStack (emulating AWS KMS).
  * The resulting metadata defined key attributes including `KeySpec: SYMMETRIC_DEFAULT` (AES-256-GCM), `KeyState: Enabled`, and `KeyUsage: ENCRYPT_DECRYPT`.
* Centralized Key Management: The generated `KeyId` uniquely identifies the CMK. The key material remains isolated within the KMS control plane and is never exposed to the client or local disk.
* Direct KMS Encryption:
  * Direct encryption via `aws kms encrypt` requires base64-encoded plaintext input (`echo -n 'hello' | base64`).
  * KMS performed the encryption internally and returned the encrypted ciphertext blob (`Nzk2OTdh...`).
* Design Constraint: Direct KMS encryption is designed exclusively for small payloads (up to 4 KB). For larger data volumes, envelope encryption must be utilized (demonstrated in Task 5).

---

## Task 5 — Envelope Encryption

## Objective
To implement envelope encryption by generating a Data Encryption Key (DEK) via KMS, encrypting local data with the plaintext DEK, and securely discarding the plaintext key material while retaining only the KMS-wrapped key. This pattern enables fast local bulk encryption while keeping primary key protection centralized within KMS.

* Commands Executed
```yaml
# 1. Request a data key from KMS (returns both plaintext and encrypted versions)
DATA_KEY_OUT=$(aws $EP kms generate-data-key --key-id $KEY_A --key-spec AES_256 \
  --query '[Plaintext,CiphertextBlob]' --output text)

# 2. Extract column 1 (plaintext DEK) and column 2 (wrapped DEK)
echo "$DATA_KEY_OUT" | awk '{print $1}' > datakey.b64
echo "$DATA_KEY_OUT" | awk '{print $2}' > datakey.enc

# 3. Decode the plaintext data key to binary format
base64 -d datakey.b64 > datakey.bin

# 4. Encrypt the file locally using the plaintext data key
openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc -pass file:./datakey.bin

# 5. Verify encrypted output and securely delete plaintext data key copies from disk
ls -la record.env.enc
rm datakey.bin datakey.b64
echo 'Only the KMS-wrapped data key (datakey.enc) remains.'
```

* Screenshot / Evidence
<img width="957" height="366" alt="Task5" src="https://github.com/user-attachments/assets/64844a21-b556-442c-8d94-92267ab0041e" />

## Technical Explanation & Analysis
* Data Key Generation:
  * The `generate-data-key` request asked KMS to create a 256-bit symmetric Data Encryption Key (DEK) under Master Key `$KEY_A`.
  * KMS returned two components: a Plaintext DEK (used for immediate local cryptographic operations) and an Encrypted/Wrapped DEK (encrypted under `$KEY_A`).
* Local Bulk Encryption:
  * The decoded binary DEK (`datakey.bin`) was used locally by OpenSSL to encrypt `record.txt`, producing `record.env.enc`
  * Because local symmetric encryption with a DEK avoids network latency, this approach scales efficiently for large files or high-throughput cloud storage workflows.
* Secure Cleanup & Key Separation:
  * Both plaintext DEK files (`datakey.bin` and `datakey.b64`) were immediately purged using `rm`.
  * Only `record.env.enc` (encrypted data) and `datakey.enc` (wrapped key) remain stored on local disk.
* Security Model: To decrypt `record.env.enc` in the future, the application must send `datakey.enc` back to KMS for unwrapping (`kms decrypt`). If KMS access is revoked or Master Key `$KEY_A` is disabled, the encrypted data becomes permanently unreadable.

---

## Task 6 — Per-Tenant Keys & Cryptographic Erasure

## Objective
To demonstrate multi-tenant cryptographic isolation by provisioning a distinct Customer Master Key (CMK) for Tenant B, followed by performing cryptographic erasure (crypto-shredding) on Tenant A's key. This task proves that disabling or scheduling key deletion instantly renders all associated encrypted payloads permanently unrecoverable.

* Commands Executed
```yaml
# 1. Provision a dedicated KMS Master Key for Tenant B
aws $EP kms create-key --description 'CCSE tenant-B master key'

# 2. Assign Tenant B's KeyId to an environment variable
KEY_B="PASTE_KEYID"

# 3. Schedule key deletion for Tenant A's Master Key ($KEY_A) with a 7-day window
aws $EP kms schedule-key-deletion --key-id $KEY_A --pending-window-in-days 7

# 4. Attempt to explicitly disable $KEY_A (returns exception as key is already pending deletion)
aws $EP kms disable-key --key-id $KEY_A

# 5. Attempt to decrypt Tenant A's wrapped data key to verify cryptographic erasure
aws $EP kms decrypt --ciphertext-blob fileb://datakey.bin.enc 2>&1 | head -3
```

* Screenshots / Evidence
<img width="770" height="371" alt="image" src="https://github.com/user-attachments/assets/891ccd61-2a6d-4f80-9586-004ce562b22e" />
<img width="457" height="47" alt="image" src="https://github.com/user-attachments/assets/2d910324-540f-4d3a-b888-381f1eccf96f" />
<img width="933" height="197" alt="image" src="https://github.com/user-attachments/assets/dd5eb5b2-c8e8-4b68-922f-e4a2f5bc0236" />
<img width="938" height="102" alt="image" src="https://github.com/user-attachments/assets/6e555caa-4e65-4ae9-87cd-02613d6af16a" />


## Technical Explanation & Analysis
* Multi-Tenant Key Isolation:
  * A dedicated CMK was generated for Tenant B (`Key_ID`) and assigned to `$KEY_B`.
  * Establishing distinct master keys per tenant creates strict cryptographic boundaries, ensuring data belonging to one tenant cannot be decrypted using another tenant's access permissions or key material.
* Cryptographic Erasure (Crypto-Shredding):
  * Invoking `aws kms schedule-key-deletion` shifted `$KEY_A` into the `PendingDeletion` state with a 7-day waiting period.
  * Attempting to run `aws kms disable-key` subsequently produced a `KMSInvalidStateException`, confirming that a key scheduled for deletion is automatically deactivated and placed out of service.
* Verification of Data Destruction:
  * Executing `aws kms decrypt` against Tenant A's wrapped data key (`datakey.bin.enc`) failed directly with `KMSInvalidStateException: key is pending deletion`.
  * Because the Master Key is unusable, unwrapping the Data Encryption Key (DEK) becomes mathematically impossible. As a result, the encrypted payload (`record.env.enc`) is cryptographically shredded—achieving provable, instant data deletion across all distributed cloud storage and backup locations without requiring physical disk overwriting.

---

## Task 7 — Integrity & Tamper-Evidence

## Objective
To demonstrate data integrity verification and tamper-evidence using cryptographic hashing (SHA-256) and a hash chain implementation. This task illustrates how minor alterations in data radically alter cryptographic digests (avalanche effect) and how hash chaining guarantees log immutability.

* Commands Executed
```yaml
# 1. Compute the SHA-256 hash of the original file
sha256sum record.txt

# 2. Duplicate file, modify payload by appending character 'x', and compare SHA-256 hashes
cp record.txt tampered.txt; echo 'x' >> tampered.txt
sha256sum record.txt tampered.txt

# 3. Simulate a tamper-evident sequential hash chain across log entries
PREV=0
for line in 'login ok' 'file read' 'export data'; do \
  PREV=$(echo -n "$PREV$line" | sha256sum | cut -d' ' -f1); \
  echo "$line | $PREV"; \
done
```

* Screenshot / Evidence
<img width="737" height="310" alt="Task7" src="https://github.com/user-attachments/assets/3cee1629-52bb-4356-8532-0f438e7000f2" />

## Technical Explanation & Analysis
* Cryptographic Hashing & Avalanche Effect:
  * Computing `sha256sum record.txt` generated the original hash `9345a32351cc1ad03e8b318059b753da6cd4e325688da97a01599b32bc945dd5`.
  * Appending a single character (`x`) to produce `tampered.txt` resulted in a completely distinct hash value (`8c8afc8a3e34425ab38ef90213102c638a82f756bd7187a03b306c5683065eb7`).
  * This demonstrates the avalanche effect, where any minute modification invalidates the digest, enabling instant detection of data tampering.
* Tamper-Evident Hash Chaining:
  * The bash loop simulates a blockchain-like sequence where each hash depends explicitly on the previous iteration's output (`$PREV`) combined with current data (`$line`):
    * `login ok` $\rightarrow$ `573f9af26d45d395a1089ef5fec4d50ccddc17c0ea4269c2c91d90929a820053`
    * `file read` $\rightarrow$ `6c3adc61ece69412b338e43d761435e95dbfc948253f8f600087b0a4c5ad2d3d`
    * `export data` $\rightarrow$ `1470ccfaf43dcab3c17d5710dc9eacbb7ac65c9f522ca98c2c503431b32da68`
  * Because every entry incorporates the hash of its predecessor, modifying or deleting an earlier record breaks all subsequent links in the chain, making history alteration mathematically detectable.

---

## Short-Answer Questions

## Q1. Compare symmetric and asymmetric encryption: speed, key distribution, and typical use.
* Speed: Symmetric encryption is computationally fast and lightweight, while asymmetric encryption is significantly slower due to complex mathematical operations.
* Key Distribution: Symmetric encryption requires sharing a single secret key over a secure channel, creating a distribution challenge. Asymmetric encryption uses a public key (distributable freely) and a private key (kept secret), eliminating key transmission risks.
* Typical Use: Symmetric encryption is used for bulk data at rest (e.g., AES for database/disk encryption). Asymmetric encryption is used for key exchange, digital signatures, and establishing secure connections (e.g., RSA/ECC in TLS handshakes).

## Q2. Why is key management described as the weakest link, not the algorithm?
Modern cryptographic algorithms (like AES-256 or RSA-2048) are mathematically robust against brute-force attacks. However, if keys are hardcoded in source code, stored in unencrypted files, exposed via over-privileged access, or improperly rotated, attackers can easily bypass the underlying mathematical security without breaking the algorithm itself.

## Q3. Explain envelope encryption and why only the master key needs hardware-grade protection.
* Explanation: Envelope encryption encrypts raw data using a fast, local Data Encryption Key (DEK), and then encrypts (wraps) that DEK using a central Key Encryption Key (KEK) / Master Key stored in a Key Management Service (KMS).
* Hardware-Grade Protection: Plaintext data keys are used briefly in memory for local bulk processing and discarded, leaving only the wrapped DEK stored alongside the data. Because all unwrapping operations must pass through the Master Key, isolating only the Master Key within a Hardware Security Module (HSM) secures the entire cryptographic system while allowing scalable, high-speed data processing.

## Q4. How does cryptographic erasure achieve provable deletion where overwriting cannot (in the cloud)?
In cloud environments, data is abstracted across distributed physical hardware, wear-leveled SSDs, snapshots, and multi-region backups, making physical bit-overwriting unfeasible and unverifiable. Cryptographic erasure (crypto-shredding) irrevocably deletes or disables the single Master Key protecting the encrypted data, rendering all distributed ciphertext blobs mathematically unrecoverable instantly across all storage locations.

## Q5. How does a hash chain make a log tamper-evident (link to tamper-proof logs, Week 6)?
A hash chain links each log entry sequentially by including the cryptographic hash of the previous log entry ($H_{n-1}$) into the calculation of the current entry's hash ($H_n$). Any modification, deletion, or reordering of an earlier log entry alters its digest and breaks the entire dependency chain downstream, instantly signaling data manipulation to auditors.

---

## Verification Command
```yaml
# 1. List all Customer Master Keys (CMKs) stored within LocalStack KMS
aws --endpoint-url=http://localhost:4566 kms list-keys

# 2. Verify the authenticity and integrity of the digital signature against the original file
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

* Screenshot / Evidence
<img width="851" height="273" alt="VerificationCommand" src="https://github.com/user-attachments/assets/c689c29a-7cf2-4b76-89ea-0f196f82db14" />

## Verification Output & Result Analysis
* Key Management Verification:
  * Executing `aws kms list-keys` outputs a JSON array containing the key IDs and Amazon Resource Names (ARNs) of all provisioned Customer Master Keys (CMKs). This confirms that both Tenant A and Tenant B master keys were successfully generated and registered within the LocalStack environment.
* Digital Signature Verification:
  * Executing the `openssl dgst` verification command against `record.txt` using `public.pem` and `record.sig` returns `Verified OK`. This confirms two critical security requirements:
    * Integrity: The underlying payload `record.txt` has not been altered or corrupted post-signing.
    * Authenticity & Non-Repudiation: The digital signature could only have been produced using the corresponding private key (`private.pem`), validating the origin of the document.

---

## Security Best-Practices Checklist
- [x] Data encrypted at rest (AES) and decryption verified.
- [x] Asymmetric keys used correctly (encrypt with public, sign with private).
- [x] Data protected in transit with TLS.
- [x] Envelope encryption used; plaintext data key not left on disk.
- [x] Per-tenant keys used; cryptographic erasure demonstrated.
- [x] Integrity verified with hashing / hash chain.

---

## Cleanup & Teardown
To ensure a clean environment and prevent leftover cryptographic materials or background container instances from persisting, the teardown procedure is executed.

* Commands Executed
```yaml
# 1. Stop the NGINX TLS web server container
docker stop tls 2>/dev/null

# 2. Remove all generated keys, certificates, ciphertext, and test files
rm -f record.* private.pem public.pem key.pem cert.pem datakey.* tampered.txt

# 3. Stop and remove the LocalStack KMS container instance
docker stop localstack && docker rm localstack
```

* Screenshot / Evidence
<img width="647" height="122" alt="image" src="https://github.com/user-attachments/assets/fe33850d-016b-413a-8d7c-fe1df187269c" />

## Technical Explanation & Analysis
* Container Sanitization: Halts and removes both active Docker containers (`tls` and `localstack`), freeing bound host ports (`8443`, `4566`) and stopping background daemon processes.
* Artifact Removal: Deletes all temporary plaintext files (`record.txt`, `tampered.txt`), generated key pairs (`private.pem`, `public.pem`, `key.pem`), certificates (`cert.pem`), encrypted data outputs (`record.rsa`, `record.env.enc`), and data encryption keys (`datakey.*`)
* Environment Restoration: Restores the local shell environment to its initial state, ensuring no sensitive key material or lingering artifacts remain stored on the local filesystem.

---

## References
* Course lecture — Week 4 (Data Protection); Week 9 (Key Management patterns).
* OpenSSL documentation — www.openssl.org/docs
* AWS KMS concepts (envelope encryption) — docs.aws.amazon.com/kms
* CSA Security Guidance v5 — Data Security & Encryption.

  













