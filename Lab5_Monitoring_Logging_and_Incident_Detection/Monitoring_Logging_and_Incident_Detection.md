# Lab 5: Monitoring Logging and Incident Detection

* **Course Code:** IKB42603 Cloud Computing Security Essentials
* **Student Name:** Sharif Ammar Izzuddin Bin Sharif Yusri
* **Student ID:** 52215124783
* **Lecturer:** Madam Nor Adani Kamal Mohamad Nasir

---

## Executive Summary

This laboratory project demonstrates the practical implementation of centralised logging, tamper-evident audit trails, and incident detection & response within a cloud-native environment using Docker and LocalStack (simulating AWS CloudWatch Logs). The primary objective is to move beyond simple log collection towards actionable security visibility — enabling the detection of multi-stage attacks through log correlation, and executing a structured incident response lifecycle.

The lab is structured into two core operational sessions aligned with CLO2 (Construct secure cloud operations that safeguard data integrity):

- **Session A (Logging & Centralisation):** Generating application-level authentication logs, shipping them to a centralised log store (CloudWatch via LocalStack), and querying logs for security-relevant activity such as failed login attempts.
- **Session B (Tamper-Proofing, Detection & Response):** Implementing hash-chained logs to guarantee tamper-evidence, correlating multiple event types to detect a brute-force-to-exfiltration incident, and executing the incident-response lifecycle (contain, collect evidence, document).

---

## Session A (Week 9) — Logging & Centralisation

### Setup — Start LocalStack

**Objective**

To provision a local cloud environment using LocalStack, simulating AWS CloudWatch Logs as the centralised log destination for this lab. This setup establishes the log group and log stream that will receive application logs in the subsequent tasks.

**Commands Executed**

```bash
docker run -d --name localstack -p 4566:4566 localstack/localstack
EP='--endpoint-url=http://localhost:4566'
aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
```

**Screenshot / Evidence**

<img width="566" height="41" alt="Setup1" src="https://github.com/user-attachments/assets/09b984cf-629f-4536-810e-087a6e15aa1e" />
<img width="527" height="20" alt="Setup2" src="https://github.com/user-attachments/assets/96137a20-f3aa-4c67-9258-fdfb8203b56d" />
<img width="662" height="77" alt="Setup3" src="https://github.com/user-attachments/assets/069c2e63-19d1-498c-bdda-fe2bb1315b0e" />

*(LocalStack container started, returning container ID `42e1d4e429f22be552bf8c1434d0eb462a098f5000cf9fd4e6f94c85ee2f79e7`; log group and log stream created successfully with no errors returned.)*

**Technical Explanation & Analysis**

- **Local Cloud Provisioning:** The `localstack/localstack` image was run as a detached Docker container, exposing port `4566` — the unified endpoint LocalStack uses to emulate various AWS services, including CloudWatch Logs.
- **Endpoint Configuration:** The `EP` variable stores the LocalStack endpoint URL, allowing subsequent AWS CLI commands to route API calls to the local emulator instead of real AWS infrastructure.
- **Log Group & Stream Creation:**
  - `create-log-group` provisions `/ccse/app` as the top-level container for log data, mirroring how CloudWatch organises logs by application/service.
  - `create-log-stream` provisions `auth` as a sub-stream within that group, representing a single source of log events (in this case, authentication activity) — consistent with the "cascading-collection" model of centralised logging discussed in Week 6.

---

### Task 1 — Generate Application Logs

**Objective**

To simulate a realistic authentication log containing both legitimate and malicious activity, including a burst of failed login attempts (representing an attacker probing for valid credentials) followed by a successful login and a large data export.

**Commands Executed**

```bash
cat > auth.log <<'EOF'
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
EOF
cat auth.log
```

**Screenshot / Evidence**

<img width="585" height="307" alt="Task1" src="https://github.com/user-attachments/assets/5fbdfbaa-1c02-446e-bfd2-00c151f089ad" />

**Technical Explanation & Analysis**

- **Log Structure:** Each log entry follows a consistent format — timestamp, event type, user, IP address, and (where applicable) additional metadata (e.g. `size=500MB`) — mirroring how real authentication systems structure audit records.
- **Benign Baseline:** The first entry (`LOGIN_OK user=ahmad ip=10.0.0.5`) represents normal, legitimate user activity, establishing a baseline against which suspicious activity can be contrasted.
- **Attack Simulation:** The four consecutive `LOGIN_FAIL` entries from `203.0.113.9` simulate a brute-force or credential-guessing attempt against the `admin` account. This is followed by a `LOGIN_OK` from the same IP, indicating the attacker eventually succeeded in authenticating.
- **Post-Compromise Action:** The final `EXPORT_DATA` entry, immediately following the successful login, represents a large (500MB) data export — a strong indicator of data exfiltration once access was gained. This sets up the correlation logic used later in Task 5 to detect the full attack chain.

---

### Task 2 — Centralise Logs (Ship to CloudWatch)

**Objective**

To ship each line of the locally generated `auth.log` to the centralised log store (CloudWatch Logs via LocalStack), simulating the cascading-collection model where logs from individual services are aggregated into a single, central source of truth for monitoring and forensics.

**Commands Executed**

```bash
TS=$(date +%s000)
while IFS= read -r line; do
  aws $EP logs put-log-events --log-group-name /ccse/app --log-stream-name auth \
    --log-events timestamp=$TS,message="$line" >/dev/null
  TS=$((TS+1000))
done < auth.log

aws $EP logs get-log-events --log-group-name /ccse/app --log-stream-name auth \
  --query 'events[].message' --output text
```

**Screenshot / Evidence**

<img width="935" height="251" alt="Task2" src="https://github.com/user-attachments/assets/0a3bfed8-fdef-4ba4-9ea2-a7cdfd6635b1" />


**Technical Explanation & Analysis**

- **Log Ingestion Loop:** Each line of `auth.log` was read individually and pushed to CloudWatch Logs via `put-log-events`, with an incrementing timestamp (`TS`) assigned to preserve chronological ordering in the centralised store.
- **Centralisation in Action:** Rather than remaining scattered on the local host, every log entry is now stored within the `/ccse/app` log group under the `auth` stream — consistent with the principle that individual services should forward logs to a central aggregator rather than retaining them locally.
- **Read-Back Verification:** The `get-log-events` command retrieves all messages back from the central store, confirming that all 7 log entries were successfully ingested and are retrievable — this read-back is the evidence that centralisation was successful.
- **Security Significance:** Centralising logs ensures that even if the source host is compromised or its local logs are deleted, a durable copy still exists in the central store, supporting both incident investigation and compliance requirements.

---

### Task 3 — Query for Security-Relevant Activity

**Objective**

To query the local log for security-relevant activity — specifically, failed login attempts — and identify the source IP responsible, while distinguishing the concept of a log (a durable record) from an event (a real-time trigger).

**Commands Executed**

```bash
# How many failed logins, and from which IP?
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c

# Distinguish a log (durable record) from an event (a trigger):
# an EVENT would be 'alert: 4 failures from 203.0.113.9' fired in near real time.
```

**Screenshot / Evidence**

<img width="586" height="66" alt="Task3" src="https://github.com/user-attachments/assets/cc93624b-6d3e-4ce6-b784-af448e614144" />


**Technical Explanation & Analysis**

- **Filtering Security-Relevant Entries:** `grep LOGIN_FAIL` isolates only the failed authentication attempts from `auth.log`, discarding unrelated entries (successful logins, data exports) that are not relevant to this specific query.
- **Field Extraction & Aggregation:** `awk '{print $4, $5}'` extracts the `user=` and `ip=` fields from each matching line, while `sort | uniq -c` groups identical combinations and counts their occurrences.
- **Result Interpretation:** The output `4 ip=203.0.113.9` confirms that all 4 failed login attempts originated from the same source IP, `203.0.113.9` — a strong early indicator of a targeted brute-force attempt rather than random, distributed noise.
- **Log vs. Event Distinction:** This query operates on the *log* — a static, durable record queried after the fact. In contrast, an *event* would be a real-time trigger (e.g. an alert fired the instant the 4th failure occurs), which is explored further in Task 5's correlation logic.

---


### Task 4 — Tamper-Proof (Hash-Chained) Logs

**Objective**

To implement a tamper-evident logging mechanism by hash-chaining each log entry to the previous entry's hash, such that any modification to a single log line breaks the chain and is immediately detectable — protecting the integrity of the audit trail even if an attacker gains access to the log file.

**Commands Executed**

```bash
PREV=0
while IFS= read -r line; do
  PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
  printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain
cat auth.chain

# Tamper test: simulate an attacker altering the EXPORT_DATA size
sed 's/500MB/5MB/' auth.log > auth.tampered

# Recompute the chain from the tampered file and compare final hashes
PREV=0
while IFS= read -r line; do
  PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
done < auth.tampered
echo "Hash akhir (tampered): $PREV"
echo "Hash akhir (original): ababa787b4bf524d9daddca8c48e4909fc105769a6f17574f42cefe8f81233cf"
```

**Screenshot / Evidence**

<img width="942" height="422" alt="Task4" src="https://github.com/user-attachments/assets/7ca8bec2-a5ed-48a8-adcd-e7c0c0c7ad69" />


**Technical Explanation & Analysis**

- **Hash Chaining Mechanism:** Each log line is concatenated with the previous line's hash (`PREV`) before being hashed with SHA-256, forming a cryptographic chain where every entry's hash is dependent on the entire history before it — identical to the tamper-evidence model used in blockchains and Merkle-style audit logs.
- **Chain Generation Result:** The resulting `auth.chain` shows each log line paired with a unique 64-character SHA-256 hash. The final entry (`EXPORT_DATA ... size=500MB`) produces the chain's terminal hash: `ababa787b4bf524d9daddca8c48e4909fc105769a6f17574f42cefe8f81233cf` — this value represents the integrity fingerprint of the entire log file at that point in time.
- **Simulated Tampering:** Using `sed`, the `EXPORT_DATA` line was altered to change the exfiltrated data size from `500MB` to `5MB` — modelling an attacker attempting to downplay the severity of a data exfiltration event by editing the log after the fact.
- **Tamper Detection:** Recomputing the hash chain from the tampered file (`auth.tampered`) and comparing its final hash against the original chain's final hash reveals a completely different value. Because SHA-256 exhibits the avalanche effect, even a single-character change propagates through every subsequent hash in the chain, making tampering immediately and unambiguously detectable — fulfilling the tamper-evidence requirement for a trustworthy audit

---

### Task 5 — Detect the Incident (Correlation)

**Objective**

To detect a multi-stage security incident by correlating multiple distinct event types from the same source IP — repeated login failures, a subsequent success, and a large data export — replicating how a SIEM identifies attack patterns that no single log entry can reveal on its own.

**Commands Executed**

```bash
IP=203.0.113.9
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)
echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"

if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
  echo 'ALERT: probable brute-force -> compromise -> data exfiltration'
fi
```

**Screenshot / Evidence**

<img width="631" height="200" alt="Task5" src="https://github.com/user-attachments/assets/89226e7a-3fdf-4a3c-b50e-fa949adee206" />


**Technical Explanation & Analysis**

- **Per-IP Event Counting:** Three separate `grep -c` counts were computed for the target IP (`203.0.113.9`) — one for each event type (`LOGIN_FAIL`, `LOGIN_OK`, `EXPORT_DATA`) — reducing the entire log history for that IP into three simple metrics: `fails=4`, `success=1`, `export=1`.
- **Correlation Logic:** The conditional statement checks whether all three thresholds are simultaneously met (`FAILS ≥ 3`, `SUCCESS ≥ 1`, `EXPORT ≥ 1`) for the *same* IP address. This is the core of correlation-based detection: no individual event (a failed login, a successful login, or a data export) is inherently malicious, but their co-occurrence from a single source within a short window strongly indicates a compromised account.
- **Alert Generation:** Since all three conditions were satisfied, the script produced `ALERT: probable brute-force -> compromise -> data exfiltration` — demonstrating how a SIEM synthesises raw log data into an actionable security event.
- **Significance:** This task demonstrates the practical value of centralised logging (Task 2) — without all relevant events being aggregated and queryable in one place, this cross-event correlation would not have been possible.

---

### Task 6 — Incident Response

**Objective**

To execute the incident-response lifecycle in reaction to the confirmed incident from Task 5 — containing the attacker's source of access and preserving a verifiable, immutable copy of the evidence for forensic and reporting purposes.

**Commands Executed**

```bash
# CONTAIN: block the attacker IP (modelled with an iptables rule)
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
 'apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2'

# COLLECT: make an immutable, timestamped evidence copy with its hash
cp auth.log evidence_$(date +%Y%m%d).log
sha256sum evidence_*.log > evidence.sha256
cat evidence.sha256
```

**Screenshot / Evidence**

<img width="785" height="216" alt="Task6" src="https://github.com/user-attachments/assets/4cf82fd8-f613-4e45-b5bb-3b44e95bcde1" />


**Technical Explanation & Analysis**

- **Containment:** A disposable Alpine container was used to model network-level containment, installing `iptables` and inserting a `DROP` rule for all inbound traffic from `203.0.113.9`. The `iptables -L INPUT -n` output confirms the rule is active (`target=DROP, source=203.0.113.9, destination=0.0.0.0/0`), representing the "cut off the attacker's access" step of incident response.
- **Evidence Collection:** The original `auth.log` was copied to a timestamped, immutable-style filename (`evidence_20260902.log`) to preserve the exact state of the log at the time of investigation, separate from any file that might still be actively written to.
- **Integrity Hashing:** A SHA-256 hash of the evidence file was generated and stored in `evidence.sha256` (`0adc5d2ac06cbbdd366099bcc0540c4c0f76946e71b52e4c99322731696a203b`). This hash acts as a cryptographic fingerprint — any future modification to the evidence file, intentional or accidental, would produce a different hash and could be detected via `sha256sum -c evidence.sha256`, ensuring chain-of-custody integrity for the evidence.
- **Alignment with IR Lifecycle:** Together, these two actions cover the "Contain" and "Collect Evidence" phases of the standard incident-response lifecycle (Detect → Contain → Collect Evidence → Document), directly following the detection confirmed in Task 5.

---

## Incident Report

**Detection**

The incident was detected through the correlation query executed in Task 5, run against the centralised logs shipped to CloudWatch Logs (LocalStack) in Task 2. The query revealed that IP `203.0.113.9` generated 4 `LOGIN_FAIL` attempts, followed by 1 `LOGIN_OK`, and 1 `EXPORT_DATA` event of 500MB, all within a short time window (09:01:10–09:01:40). No single log line indicated malicious activity on its own; only when the events were correlated by IP and sequence did the brute-force-followed-by-exfiltration pattern become visible, triggering the alert: *"ALERT: probable brute-force -> compromise -> data exfiltration."*

**Analysis**

The log pattern shows the attacker attempting to log in as `admin` four consecutive times before succeeding, consistent with a brute-force or credential-guessing attack. Immediately after gaining access, the attacker performed a 500MB `EXPORT_DATA` action — behaviour inconsistent with normal login activity, and strongly suggestive of data exfiltration of user or system data. The tight timing between the successful login (09:01:22) and the export (09:01:40) further supports the conclusion that the export was a direct consequence of the compromised session, not routine activity.

**Containment**

The attacker's IP (`203.0.113.9`) was blocked using an iptables rule (`iptables -A INPUT -s 203.0.113.9 -j DROP`), modelled via a disposable Alpine container in Task 6. This prevents any further inbound traffic from the identified source from reaching the system, halting continued unauthorised access.

**Evidence & Integrity**

A timestamped copy of the original log (`auth.log`) was preserved as `evidence_20260902.log`, and its SHA-256 hash was recorded in `evidence.sha256` to establish a verifiable chain of custody. Separately, the log's integrity was validated as tamper-evident via hash-chaining in Task 4: when the `EXPORT_DATA` line was altered (data size changed from 500MB to 5MB, simulating an attacker covering their tracks), the recomputed final chain hash differed completely from the original chain's final hash, proving that any unauthorised modification to the log is detectable.

**Lesson Learned**

Raw logs alone are insufficient to detect complex, multi-stage incidents — correlation across multiple event types (failed logins, a successful login, and a data export) was required to reveal the true attack narrative, which no individual log line exposed on its own. This reinforces the need for centralised, queryable logging combined with correlation-based detection. Additionally, the logging system must be tamper-evident and its evidence stored/hashed separately from the live application, ensuring that an attacker who compromises the application cannot also rewrite the audit trail used to investigate them.

---

## Short-Answer Questions

**Q1. What is the difference between a log and an event? Give an example of each from this lab.**

A log is a durable record of every activity that occurs, stored for later reference and forensics — for example, each line in `auth.log` (e.g. `LOGIN_FAIL user=admin ip=203.0.113.9`). An event is a real-time trigger generated when a specific condition is met — for example, the `ALERT: probable brute-force -> compromise -> data exfiltration` output produced in Task 5, which fired once the correlation thresholds (≥3 fails, ≥1 success, ≥1 export) were satisfied.

**Q2. Why must audit logs be tamper-proof, and how does a hash chain achieve this?**

Audit logs must be tamper-proof so they can be trusted as valid evidence during forensics or compliance audits — if an attacker can alter logs to hide their tracks, the logs become useless as evidence. A hash chain achieves this by linking each line's hash to the hash of the previous line (`PREV`), forming a dependent chain. Any change to a single line (even one character) changes that line's hash, which in turn changes every subsequent hash in the chain, causing the final hash to differ from the original — instantly revealing that tampering occurred, as demonstrated in Task 4.

**Q3. How did correlation detect an incident that no single log line revealed?**

Individually, each log line looked benign: a failed login is common, a successful login is normal, and a data export could be routine. It was only by correlating multiple event types from the same IP within the same time window — counting `LOGIN_FAIL` ≥3, `LOGIN_OK` ≥1, and `EXPORT_DATA` ≥1 — that the full attack narrative (brute-force → compromise → exfiltration) emerged. This mirrors how a real SIEM works: no single event triggers an alert, but the combination and sequence of events does.

**Q4. List the incident-response steps you performed and the goal of each.**

- **Detect** — Ran the correlation query (Task 5) to identify the suspicious pattern of repeated failures, a success, and a large export from the same IP. Goal: confirm an incident is occurring.
- **Contain** — Blocked the attacker's IP using an iptables DROP rule (Task 6). Goal: stop further malicious activity from that source.
- **Collect Evidence** — Copied `auth.log` to a timestamped evidence file and generated its SHA-256 hash (Task 6). Goal: preserve an immutable, verifiable record of what happened for forensics.
- **Document** — Wrote this incident report covering detection, analysis, containment, and evidence. Goal: create a clear timeline and record for future reference, compliance, and lessons learned.

**Q5. How do the same logs serve both security monitoring and compliance evidence?**

The same centralised, tamper-evident logs serve dual purposes: for security monitoring, they allow real-time and retrospective detection of malicious patterns (e.g. brute-force attempts, unauthorised data exports) through querying and correlation. For compliance, the same logs — being centralised, timestamped, and hash-chained for integrity — serve as auditable proof that activities were recorded accurately and have not been altered, satisfying regulatory requirements for record-keeping, accountability, and incident traceability.

---

### Verification Command

**Objective**

To perform a final verification that the centralised log group is correctly provisioned in LocalStack, and that the evidence file collected in Task 6 has not been tampered with — confirming both the availability of the logging infrastructure and the integrity of the collected evidence.

**Commands Executed**

```bash
aws --endpoint-url=http://localhost:4566 logs describe-log-groups
sha256sum -c evidence.sha256
```

**Screenshot / Evidence**

<img width="652" height="255" alt="VC" src="https://github.com/user-attachments/assets/487d33fb-0e04-4e51-8c19-194a4df9d6d9" />


**Technical Explanation & Analysis**

- **Log Group Verification:** The `describe-log-groups` call confirms that the `/ccse/app` log group exists within LocalStack, returning its metadata — including `creationTime`, `arn`, and `storedBytes: 397`, which reflects the accumulated log data shipped during Task 2. This confirms the centralised logging infrastructure remained available and correctly provisioned throughout the lab.
- **Evidence Integrity Check:** The `sha256sum -c evidence.sha256` command recomputes the SHA-256 hash of `evidence_20260902.log` and compares it against the hash recorded in Task 6. The output `evidence_20260902.log: OK` confirms the evidence file's hash matches exactly, proving the file has not been altered since it was collected — validating the chain of custody for forensic and reporting purposes.
- **Significance:** Together, these two checks close the loop on the lab's core objectives — demonstrating that (1) the centralised log store remains a reliable source of truth, and (2) the tamper-evidence mechanism applied to the evidence file is functioning as intended and can be independently re-verified at any time.

---

## Security Best-Practices Checklist

- [x] Logs are centralised, not left scattered on each host.
- [x] Security-relevant activity (failed logins) can be queried.
- [x] Logs are tamper-evident (hash chain) and forwarded to a separate store.
- [x] An incident is detected by correlating multiple events.
- [x] Incident response performed: contain, collect evidence, document.

---

## Cleanup & Teardown

**Objective**

To remove all lab-generated files and stop/remove the LocalStack container, returning the environment to a clean state after all evidence and deliverables have been collected.

**Commands Executed**

```bash
rm -f auth.log auth.chain auth.tampered evidence_*.log evidence.sha256
docker stop localstack && docker rm localstack
```

**Screenshot / Evidence**

<img width="607" height="96" alt="Cleanup" src="https://github.com/user-attachments/assets/fc79a6d7-7ea5-4efb-a55c-79c4eada672a" />


**Technical Explanation & Analysis**

- **File Cleanup:** All lab-generated artefacts — the raw log (`auth.log`), the hash-chained log (`auth.chain`), the tampered copy (`auth.tampered`), and the evidence files (`evidence_*.log`, `evidence.sha256`) — were removed from the local filesystem, since their contents had already been captured as screenshots/evidence for the report.
- **Container Teardown:** The `localstack` container was stopped and removed (`docker stop` followed by `docker rm`), both confirmed by the repeated `localstack` output, releasing the resources (port `4566`, memory) it was using.
- **Significance:** Performing cleanup after a lab is good operational hygiene — it prevents leftover containers or stale credentials/files from interfering with future labs (as was encountered earlier when a leftover `localstack` container caused a naming conflict), and ensures the environment starts fresh for subsequent exercises.

---

## References

- Course lecture — Week 6 (Monitoring, Auditing & Management); Weeks 10–11 (compliance evidence).
- Amazon CloudWatch Logs concepts — [docs.aws.amazon.com/AmazonCloudWatch/latest/logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs)
- OWASP Logging Cheat Sheet — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org)
- CSA Security Guidance v5 — Security Monitoring domain.





