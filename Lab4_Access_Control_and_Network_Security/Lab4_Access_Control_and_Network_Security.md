# Lab 4: Access Control & Network Security

* **Course Code:** IKB42603 Cloud Computing Security Essentials
* **Student Name:** Sharif Ammar Izzuddin Bin Sharif Yusri
* **Student ID:** 52215124783
* **Lecturer:** Madam Nor Adani Kamal Mohamad Nasir

---

## Executive Summary
This laboratory project demonstrates the practical implementation of Access Control, Network Security, and Container Hardening within cloud-native environments using Docker and Kubernetes (`kind`). The primary objective is to enforce defense-in-depth strategies, moving from Identity Management (Who gets in) to Infrastructure Security (What they can reach and exploit).

The lab is structured into two core operational sessions aligned with CLO2 (Construct secure cloud operations that safeguard data integrity):
* Session A (Identity & Access Control): Enforcing authentication, multi-factor authentication (MFA/TOTP), and Kubernetes Role-Based Access Control (RBAC).
* Session B (Network & Compute Hardening): Implementing multi-tier network segmentation, default-deny firewall policies, container runtime hardening, and vulnerability scanning.

---

## Session A (Week 7) — Authentication & Authorization

## Task 1 — Authentication: a Password-Protected Service
### Objective
To enforce HTTP Basic Authentication at the web server layer using Nginx and htpasswd. This task demonstrates how to secure sensitive web application endpoints by requiring client identity verification prior to granting access, validating access control behavior for both authenticated and unauthenticated requests.

* Commands Executed
```yaml
# 1. Create a password file (user: student)
docker run --rm httpd:alpine htpasswd -nbB student 'P@ssword!' > htpasswd.txt

# 2. Serve a page that requires authentication
cat > default.conf <<'EOF'
server { listen 80;
location / { auth_basic "Restricted";
auth_basic_user_file /etc/nginx/.htpasswd;
return 200 'Authenticated OK\n'; } }
EOF

# 3. Deploy the Nginx authentication service container
docker run --rm -d --name authsvc -p 8080:80 \
  -v $(pwd)/default.conf:/etc/nginx/conf.d/default.conf \
  -v $(pwd)/htpasswd.txt:/etc/nginx/.htpasswd nginx

# 4. Verify access control behavior
curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080
curl -s -u student:'P@ssword!' http://localhost:8080
```

* Screenshot / Evidence
<img width="702" height="518" alt="Task1" src="https://github.com/user-attachments/assets/20cbd667-a9f7-4cda-a04f-8fe597e4f463" />
<img width="636" height="85" alt="Task1_2" src="https://github.com/user-attachments/assets/d263f3a1-fdfe-4014-a3df-3030cf227717" />

### Technical Explanation & Analysis
* Credential Provisioning: The `htpasswd` utility was executed inside an `httpd:alpine` container to create a `.htpasswd` file containing the user `student`.
  * The `-B` flag enforces bcrypt hashing, protecting stored credentials against brute-force and offline dictionary attacks.
* Nginx Auth Enforcement: The `default.conf` configuration was created to enforce authentication on the root endpoint using the `auth_basic` directive.
  * The `auth_basic_user_file` directive references `/etc/nginx/.htpasswd` inside the container to validate HTTP Authorization headers.
* Access Control Verification:
  * Executing `curl` without credentials returned `no-creds: 401`, proving that unauthenticated access is blocked at the gateway level.
  * Executing `curl -u student:'P@ssword!'` supplied valid credentials via HTTP Basic headers, returning `Authenticated OK`with an HTTP `200` status code.

---

## Task 2 — Add a Second Factor (MFA / TOTP)
### Objective

To implement Multi-Factor Authentication (MFA) using Time-based One-Time Passwords (TOTP). This task demonstrates how adding a second authentication factor combines "something you know" (password) with "something you have" (a TOTP secret/authenticator token) to defeat single-factor credential compromise attacks.

* **Commands Executed**

```bash
# 1. Generate a Base32 shared secret and compute the current 6-digit TOTP code
SECRET=$(head -c20 /dev/urandom | base32)
CODE=$(oathtool --totp -b "$SECRET")
echo "Code: $CODE"

# 2. Validate the dynamic TOTP code against the expected secret
[ "$CODE" = "$(oathtool --totp -b "$SECRET")" ] && echo 'MFA OK' || echo 'MFA FAILED'
```

* Screenshot / Evidence
<img width="771" height="125" alt="task2" src="https://github.com/user-attachments/assets/c94df54d-d97b-415b-b712-841bc5fdd361" />

### Technical Explanation & Analysis
* Shared Secret Generation: A secure 20-byte random seed was pulled from `/dev/urandom` and encoded into Base32 to establish the shared secret key between the client and authentication server.
* TOTP Algorithm (RFC 6238): The `oathtool` utility uses the shared secret and the current UNIX timestamp (divided into 30-second time windows) to calculate a dynamic 6-digit OTP code (`705287`).
* Factor Verification: Comparing the supplied `$CODE` variable against a freshly calculated `oathtool` response returned `MFA OK`, confirming valid multi-factor verification.
* Attack Surface Reduction: Implementing TOTP neutralizes credential-based attacks such as password spraying, credential stuffing, and dictionary attacks. Even if an attacker obtains a user's static password, access remains blocked without physical access to the TOTP token generator.

---

## Task 3 — Role-Based Access Control (Kubernetes RBAC)

### Objective

To enforce fine-grained authorization within a Kubernetes cluster using Role-Based Access Control (RBAC). This task demonstrates how to define scoped permissions for a ServiceAccount within a specific namespace and verify the principle of least privilege using authorization queries.

* **Commands Executed**

```bash
# 1. Clean up old cluster and spin up a new Kind cluster
kind delete cluster --name ccse-lab4 2>/dev/null
kind create cluster --name ccse-lab4

# 2. Create target namespace and ServiceAccount
kubectl create namespace app
kubectl create serviceaccount dev -n app

# 3. Define Role and bind it to the ServiceAccount
kubectl create role dev-role -n app --verb=get,list --resource=pods
kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev

# 4. Impersonate ServiceAccount to test permission enforcement
SA="system:serviceaccount:app:dev"
kubectl auth can-i list pods -n app --as=$SA
kubectl auth can-i create deploy -n app --as=$SA
kubectl auth can-i delete pods -n app --as=$SA
```

* Screenshot / Evidence
<img width="700" height="620" alt="Task3" src="https://github.com/user-attachments/assets/a62af8c5-c3d4-4d18-b073-d7c1141562c9" />

### Technical Explanation & Analysis
* Cluster & Identity Provisioning: A Kubernetes cluster (`ccse-lab4`) was deployed using `kind`. Within the `app` namespace, a dedicated `dev` ServiceAccount was created to act as the workload/user identity.
* RBAC Policy Scoping:
  * Role (`dev-role`): Created within the `app` namespace granting read-only verbs (`get`, `list`) strictly restricted to the `pods` resource.
  * RoleBinding (`dev-rb`): Binds `dev-role` directly to `system:serviceaccount:app:dev`, scoping its authority exclusively to the `app` namespace.
* Least Privilege Verification (`kubectl auth can-i`):
  * `list pods` (`yes`): Explicitly authorized by `dev-role`.
  * `create deploy` (`no`): Blocked because deployments are not listed under allowed resources.
  * `delete pods` (`no`): Blocked because `delete` is not included in the granted verbs.
* Security Value: Enforces strict authorization and compartmentation, ensuring compromised service accounts or identity tokens cannot perform unauthorized actions or escalate privileges across the cluster.

---

## Session B (Week 8) — Network Security & Hardening

## Task 4 — Network Segmentation & Isolation (Docker Networks)

### Objective

To enforce network segmentation between multi-tier containerized application components using Docker bridge networks. This task demonstrates how isolating frontend, application, and database tiers prevents unauthorized cross-tier lateral movement while permitting necessary inter-service communication.

* **Commands Executed**

```bash
# 1. Create isolated bridge networks for frontend and backend tiers
docker network create frontend-net
docker network create backend-net

# 2. Deploy database container exclusively on backend-net
docker run -d --name db --network backend-net redis:alpine

# 3. Deploy app server on backend-net and attach it to frontend-net (dual-homed)
docker run -d --name app --network backend-net nginx:alpine
docker network connect frontend-net app

# 4. Deploy public web container exclusively on frontend-net
docker run -d --name web --network frontend-net nginx:alpine

# 5. Verify isolation: Test if web tier can directly access the database (Expected: BLOCKED)
docker exec web sh -c 'apk add -q curl; curl -m 3 db:6379 || echo BLOCKED'

# 6. Verify connectivity: Test if application tier can reach the database (Expected: REACHABLE)
docker exec app sh -c 'apk add -q curl; nc -z -w3 db 6379 && echo REACHABLE'
```

* Screenshot / Evidence
<img width="580" height="100" alt="Task4_1" src="https://github.com/user-attachments/assets/e54426fd-483b-490a-923f-1be971e5eb71" />
<img width="710" height="287" alt="Task4_2" src="https://github.com/user-attachments/assets/2196e580-c4e4-409b-b5a7-b0570de151de" />

### Technical Explanation & Analysis
* Network Topography Creation:
  * Two distinct user-defined bridge networks were created: `frontend-net` and `backend-net`.
  * The `db` container (Redis) resides strictly on `backend-net`, preventing direct exposure to external or frontend containers.
  * The `web` container (Nginx) resides strictly on `frontend-net`.
  * The `app` container acts as a dual-homed gateway attached to both `frontend-net` and `backend-net`.
* Network Boundary Enforcement:
  * Frontend-to-Database Traffic (`web` -> `db`): Executing a request from `web` to `db` failed with `Could not resolve host: db` and outputted `BLOCKED`. Docker's embedded DNS server does not resolve container names across isolated networks, ensuring network-level microsegmentation.
  * App-to-Database Traffic (`app` -> `db`): Executing `nc -z -w3 db 6379` from `app` returned `REACHABLE`, confirming active connectivity across shared network interfaces.
* Security Value: Enforces the principle of least privilege at the network layer. If the public-facing `web` container suffers a compromise, an attacker cannot directly pivot or exfiltrate data from the backend database container (`db`).

---

## Task 5 — Host & Container Firewall Configuration (iptables)

### Objective

To enforce inbound traffic filtering at the container network level using `iptables`. This task demonstrates how to configure a default-deny host firewall policy to restrict inbound connections exclusively to authorized ports (HTTPS) and local loopback traffic.

* **Commands Executed**

```bash
# Execute container with Linux network capabilities and apply iptables rules
docker run --rm --cap-add=NET_ADMIN alpine sh -c '
apk add -q iptables; \
iptables -P INPUT DROP; \
iptables -A INPUT -p tcp --dport 443 -j ACCEPT; \
iptables -A INPUT -i lo -j ACCEPT; \
iptables -L INPUT -n'

* Screenshot / Evidence
<img width="621" height="187" alt="Task5" src="https://github.com/user-attachments/assets/567e99c9-8a46-46f8-9217-a8201fdb633c" />

### Technical Explanation & Analysis
* Network Topography Creation:
  * Two distinct user-defined bridge networks were created: `frontend-net` and `backend-net`.
  * The `db` container (Redis) resides strictly on `backend-net`, preventing direct exposure to external or frontend containers.
  * The `web` container (Nginx) resides strictly on `frontend-net`.
  * The `app` container acts as a dual-homed gateway attached to both frontend-net and `backend-net`.
* Network Boundary Enforcement:
  * Frontend-to-Database Traffic (`web` -> `db`): Executing a request from `web` to `db` failed with `Could not resolve host: db` and outputted `BLOCKED`. Docker's embedded DNS server does not resolve container names across isolated networks, ensuring network-level microsegmentation.
  * App-to-Database Traffic (`app` -> `db`): Executing `nc -z -w3 db 6379` from `app` returned `REACHABLE`, confirming active connectivity across shared network interfaces.
* Security Value: Enforces the principle of least privilege at the network layer. If the public-facing `web` container suffers a compromise, an attacker cannot directly pivot or exfiltrate data from the backend database container (`db`).
```

* Screenshot / Evidence
<img width="621" height="187" alt="Task5" src="https://github.com/user-attachments/assets/5a978bb7-7dbf-4ff5-9de0-6b2a9fed5449" />

### Technical Explanation & Analysis
* Container Capability Provisioning:
  * The `--cap-add=NET_ADMIN` flag grants the Alpine container the specific Linux capability required to manipulate network stack configurations and interface filtering rules without granting full root privileges (`--privileged`).
* Firewall Policy & Rule Enforcement:
  * Default Policy (`iptables -P INPUT DROP`): Sets a baseline Default Deny posture. Any incoming packet that does not explicitly match an rule in the `INPUT` chain is dropped by default.
  * HTTPS Allowance (`-p tcp --dport 443 -j ACCEPT`): Explicitly permits inbound encrypted web traffic arriving on TCP port `443`.
  * Loopback Allowance (`-i lo -j ACCEPT`): Permits internal loopback traffic to allow local processes on the container to communicate seamlessly with `127.0.0.1`.
* Ruleset Verification:
  * Running `iptables -L INPUT -n` confirms that `Chain INPUT (policy DROP)` is active and displays the `ACCEPT` targets configured exclusively for TCP port `443` and local interface operations.
* Security Value: Enforces strict packet-level filtering directly within host and container environments. Implementing default-deny firewall policies drastically reduces the attack surface by dropping port scans, unauthorized connections, and unapproved service probes.

---

## Task 6 — Container Hardening & Image Scanning

### Objective

To apply defense-in-depth security controls at the container runtime layer and perform vulnerability scanning on container images. This task demonstrates how to restrict container capabilities, enforce non-root user execution, make the root filesystem read-only, and audit images for known CVEs using Trivy.

* **Commands Executed**

```bash
# 1. Deploy a hardened container with strict runtime security controls
docker run -d --name hardened \
  --user 1000:1000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp \
  nginxinc/nginx-unprivileged

# 2. Inspect container configuration to verify user and filesystem state
docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'

# 3. Perform vulnerability scanning on container images using Trivy
docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine | head -20
```

* Screenshot / Evidence
<img width="692" height="347" alt="Task6_1" src="https://github.com/user-attachments/assets/524794e5-117e-4d58-8d29-aefc69df68c6" />
<img width="820" height="66" alt="Task6_2" src="https://github.com/user-attachments/assets/05156a25-f4d8-4480-a0e7-0ddd0bb89583" />
<img width="781" height="182" alt="Task6_3" src="https://github.com/user-attachments/assets/5d50092b-4df0-4313-bbd9-5201beea55d3" />
<img width="605" height="180" alt="Task6_4" src="https://github.com/user-attachments/assets/ee4e9adf-2e30-4801-8443-67b766a932cb" />

### Technical Explanation & Analysis
* Runtime Hardening Flags:
  * --user 1000:1000: Forces execution under an unprivileged UID/GID, ensuring processes do not execute as root within the container environment.
  * --read-only: Mounts the container root filesystem as immutable, preventing malware persistence, arbitrary file modifications, or unauthorized payload drops.
  * --cap-drop ALL: Strips all Linux kernel capabilities (such as CAP_SYS_ADMIN and CAP_NET_RAW), severely limiting allowed system calls.
  * --security-opt no-new-privileges: Blocks processes from escalating privileges via setuid or setgid binaries.
  * --tmpfs /tmp: Mounts a volatile in-memory directory for necessary temporary file operations without compromising root filesystem immutability.
* Hardening Verification:
  * Executing docker inspect confirmed User=1000:1000 and ReadOnly=true, validating that runtime restrictions were successfully registered by the Docker daemon.
* Vulnerability Management & Results:
  * Scanning nginx:alpine using Aqua Security's trivy tool evaluated the image against vulnerability databases for HIGH and CRITICAL severity CVEs.
  * The resulting Report Summary confirmed 0 vulnerabilities found for nginx:alpine (alpine 3.24.1), verifying that the base image is clean and suitable for deployment.
    
---

# 2. Short-Answer Questions

**Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.**

* **Authentication (Task 1):** Verifies *who* a user or entity is (identity verification). In Task 1, Nginx uses HTTP Basic Auth (`.htpasswd`) to verify credentials (`student:P@ssword!`). If valid, identity is confirmed; if invalid, access is denied (`401 Unauthorized`).
* **Authorization (Task 3):** Determines *what* an authenticated identity is permitted to do (privilege control). In Task 3, Kubernetes RBAC evaluates permissions for `system:serviceaccount:app:dev` using `kubectl auth can-i`. Even though the identity exists, it is only authorized to `list pods` (`yes`), while `create deploy` and `delete pods` are forbidden (`no`).

---

**Q2. Why is MFA so effective, and which attacks does it defeat?**

* **Why it is effective:** MFA requires two distinct categories of authentication factors: "something you know" (static password) and "something you have" (a dynamic TOTP token generated via secret key).
* **Attacks defeated:**
  * **Credential Stuffing & Password Reuse:** Attackers with leaked passwords cannot authenticate without physical access to the TOTP generator.
  * **Brute-Force & Dictionary Attacks:** Cracking the static password alone is insufficient for access.
  * **Password Spraying:** Attacks targeting common passwords across multiple accounts fail at the second factor layer.

---

**Q3. How does network segmentation limit the damage of a compromised web server?**

* **Containment & Blast Radius Reduction:** Network segmentation isolates network tiers into independent zones (e.g., `frontend-net` and `backend-net`).
* **Prevention of Lateral Movement:** If the public-facing `web` container on `frontend-net` is compromised, network boundaries prevent direct access or DNS resolution (`db:6379`) to the backend database (`db`) located exclusively on `backend-net`.
* **Enforcing Gateways:** Access to critical resources must route through explicit, dual-homed application nodes (`app`), preventing unauthorized direct probing or exfiltration from external entry points.

---

**Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?**

* **Default-Deny Achievement:** A default-deny policy (`iptables -P INPUT DROP`) establishes a baseline security posture where all incoming network packets are dropped unless explicitly permitted by an inbound rule. This eliminates exposure to unexpected or unmapped service ports.
* **Relation to Cloud Security Groups:** AWS Security Groups, Azure Network Security Groups (NSGs), and GCP Firewall Rules operate on the same default-deny principal. By default, all inbound traffic to cloud instances/resources is blocked until explicit allow-rules (e.g., allow TCP port 443) are defined.

---

**Q5. List the hardening measures you applied and the attack surface each one removes.**

* **`--user 1000:1000`:** Removes execution as `root` inside the container, preventing container-to-host privilege escalation attacks.
* **`--read-only`:** Makes the root filesystem immutable, preventing attackers from downloading malicious tools, modifying binary files, or establishing persistence.
* **`--cap-drop ALL`:** Drops all Linux kernel capabilities (e.g., `CAP_SYS_ADMIN`), removing the ability to exploit kernel-level vulnerabilities or perform unauthorized system calls.
* **`--security-opt no-new-privileges`:** Blocks execution of `SUID`/`SGID` binaries, preventing processes from gaining elevated privileges during execution.
* **`--tmpfs /tmp`:** Restricts temporary file writes strictly to volatile memory, preventing persistent file artifacts on disk.
* **Vulnerability Scanning (`trivy`):** Identifies base image `HIGH` and `CRITICAL` CVEs before deployment, preventing exploitation of known software supply chain vulnerabilities.

---

## Additional Verification Commands

### Objective

To perform deep configuration inspection on active Kubernetes RBAC bindings and Docker container security parameters. This task verifies the exact resource manifests and runtime capability drop states enforced during deployment.

* **Commands Executed**

```bash
# 1. Inspect the Kubernetes RoleBinding YAML structure in the app namespace
kubectl get rolebinding dev-rb -n app -o yaml

# 2. Inspect the Linux capabilities dropped from the hardened Docker container
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'
```

* Screenshot / Evidence
<img width="602" height="332" alt="VC" src="https://github.com/user-attachments/assets/e7862743-d136-491e-b492-ca45b657c0bf" />

### Technical Explanation & Analysis
* Kubernetes RoleBinding Inspection (`kubectl get rolebinding dev-rb -n app -o yaml`):
  * Role Association (`roleRef`): Confirms that the `RoleBinding` accurately targets `kind: Role` named `dev-role` under the `rbac.authorization.k8s.io` API group.
  * Subject Mapping (`subjects`): Validates that the binding applies strictly to the `ServiceAccount`named `dev` isolated within the `app` namespace.
  * Declarative Integrity: Outputting the YAML manifest proves the RBAC structure was applied correctly in the API server, ensuring non-repudiation of permission bindings.
* Capability Drop Verification (`docker inspect hardened --format ...`):
  * JSON Inspection: Extracting `.HostConfig.CapDrop` returned `["ALL"]`.
  * Security Enforcement: Confirms that the Docker daemon successfully dropped all Linux kernel capabilities from the container's process tree upon creation, preventing privilege escalation vulnerabilities at runtime.

---

# Security Best-Practices Checklist

## Overview

The following checklist verifies that all core security controls and defense-in-depth principles have been successfully implemented, validated, and documented across Tasks 1 through 6.

* **Checklist Table**

| Status | Security Best-Practice Control | Implementation & Verification Evidence |
| :---: | :--- | :--- |
| **[x]** | **Service requires authentication**<br>*(unauthenticated requests rejected)* | **Task 1:** Enforced HTTP Basic Auth via Nginx (`.htpasswd`). Unauthenticated `curl` requests were blocked with `HTTP 401 Unauthorized`, while valid credentials returned `HTTP 200 OK`. |
| **[x]** | **MFA / second factor implemented and validated** | **Task 2:** Configured TOTP generation via `oathtool`. Verified dynamic code execution and secret validation, resulting in `MFA OK`. |
| **[x]** | **Authorization enforced by RBAC**<br>*(least privilege; unauthorized actions denied)* | **Task 3:** Created Kubernetes `Role` and `RoleBinding` for `app:dev` ServiceAccount. `kubectl auth can-i` confirmed `list pods` (`yes`), while `create deploy` and `delete pods` were denied (`no`). |
| **[x]** | **Network segmented so the data tier is unreachable from the front tier** | **Task 4:** Isolated container tiers using `frontend-net` and `backend-net`. Verified `web` (frontend) cannot reach `db` (`BLOCKED`), while `app` (middle-tier) retains connection (`REACHABLE`). |
| **[x]** | **Default-deny firewall with explicit allow rules** | **Task 5:** Applied `iptables -P INPUT DROP` baseline inside container. Explicitly allowed inbound HTTPS traffic (TCP port `443`) and local loopback (`lo`). |
| **[x]** | **Container hardened:**<br>*(non-root, minimal, capabilities dropped, read-only; image scanned)* | **Task 6:** Deployed container with `--user 1000:1000`, `--read-only`, `--cap-drop ALL`, and `--security-opt no-new-privileges`. Scanned `nginx:alpine` using `trivy` (`0` vulnerabilities). |

---

## Environment Cleanup & Decommissioning

### Objective

To safely remove all temporary containers, custom bridge networks, and local Kubernetes clusters created during the lab exercise. This step ensures environment sanitization, prevents resource leakage, and restores the host system to its baseline state.

* **Commands Executed**

```bash
# 1. Force removal of all deployed containers across tasks
docker rm -f authsvc db app web hardened 2>/dev/null

# 2. Remove isolated custom Docker bridge networks
docker network rm frontend-net backend-net 2>/dev/null

# 3. Teardown local Kubernetes cluster environment
kind delete cluster --name ccse-lab4
```

* Screenshot / Evidence
<img width="465" height="197" alt="CleanUp" src="https://github.com/user-attachments/assets/2c30c04f-9c23-46a4-9a08-dbe777206dd4" />

### Technical Explanation & Analysis
* Container Termination:
  * Executing `docker rm -f` stopped and permanently purged running instances (`db`, `app`, `web`, and `hardened`). Redirecting `2>/dev/null` gracefully handled missing containers like `authsvc` without throwing errors.
* Network Purge:
  * Removing `frontend-net` and `backend-net` cleared custom bridge interfaces from the Docker daemon, ensuring no residual iptables rules or routing tables remained.
* Kubernetes Cluster Teardown:
  * Executing `kind delete cluster --name ccse-lab4` successfully unmounted and deleted the control plane node (`ccse-lab4-control-plane`), purging all deployed namespaces, service accounts, and RBAC policies.

---

# References

* Course lectures — Week 5 (Access Control), Week 9 (Network Security patterns).
* Docker security — docs.docker.com/engine/security
* CIS Docker / Kubernetes Benchmarks — www.cisecurity.org
* CSA Security Guidance v5 — Infrastructure & Networking; IAM.









































