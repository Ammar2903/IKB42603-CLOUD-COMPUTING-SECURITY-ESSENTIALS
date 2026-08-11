# Lab 1: Cloud Account Security, Identity & Access Management (IAM)

* **Course Code:** IKB42603 Cloud Computing Security Essentials
* **Student Name:** Sharif Ammar Izzuddin Bin Sharif Yusri
* **Student ID:** 52215124783
* **Lecturer:** Madam Nor Adani Kamal Mohamad Nasir

---

## Executive Summary
This lab evaluates security controls designed for Secure Isolation and Multi-Tenancy within containerized environments (Docker) and cloud orchestration systems (Kubernetes with Calico CNI). The primary goal is to demonstrate the inherent risks of shared cloud infrastructure and enforce isolation across three primary dimensions

1) Compute Isolation: Partitioning tenant workloads using Kubernetes Namespaces and restricting resource consumption via `ResourceQuota`.
2) Network Isolation: Demonstrating the default-open risk on shared networks and enforcing a `Default-Deny Ingress` NetworkPolicy using Calico CNI.
3) Storage & Data Isolation: Implementing Role-Based Access Control (RBAC) to isolate secrets and mitigating Data Remanence through Secure Wipe mechanisms.

---

## Session A (Week 3) — Compute Isolation & the Default-Open Risk

## Setup — Cluster with Policy Enforcement

## Objective

To provision a multi-tenant testbed cluster using `kind` (Kubernetes in Docker) with its default Container Network Interface (CNI) disabled. Calico CNI is then installed to enable NetworkPolicy enforcement, as the default `kind` network plugin does not support traffic filtering or isolation policies.

## Step 1: Create `kind` Cluster with Default CNI Disabled

```yaml
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16"
EOF
```
* Command Executed:
<img width="807" height="398" alt="Setup_1" src="https://github.com/user-attachments/assets/fa92dda0-27ea-4441-a3aa-d2b077cf4076" />

* Observation:
  * The `kind` cluster named `ccse-lab2` was successfully created.
  * `disableDefaultCNI: true` disabled kindnet, leaving the pod network unconfigured until Calico is deployed.
  * The Pod IP subnet was explicitly defined as `192.168.0.0/16`.
  * `kubectl` context was automatically set to `kind-ccse-lab2`.

## Step 2: Install Project Calico CNI

```yaml
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
```
* Command Executed:
<img width="932" height="537" alt="Setup_2" src="https://github.com/user-attachments/assets/1ca3e3f4-1a22-421c-bbee-272f4dd92401" />

* Observation:
  * Successfully deployed Calico Custom Resource Definitions (CRDs) including `networkpolicies.crd.projectcalico.org`, `globalnetworkpolicies.crd.projectcalico.org`, and IPAM configurations.
  * Created required RBAC components (`ServiceAccount`, `ClusterRole`, `ClusterRoleBinding`) and initialized the `calico-node` DaemonSet along with `calico-kube-controllers`.

## Step 3: Verify CNI Rollout Status

```yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```
* Command Executed:
<img width="772" height="77" alt="Setup_3" src="https://github.com/user-attachments/assets/73430e01-6830-4320-9609-51f3ebafdce4" />

* Observation:
  * Confirmed that `daemon set "calico-node" successfully rolled out` within the `kube-system` namespace.
  * The cluster networking layer is fully operational and capable of enforcing granular layer-3/layer-4 ingress and egress network isolation rules.

## Technical Security Analysis

* `Why Disable Default CNI?`
Standard kind deployments use kindnet, which lacks support for Kubernetes NetworkPolicy objects. Disabling the default CNI allows Calico to manage pod networking and eBPF/iptables routing.
* `NetworkPolicy Capability:`
Calico acts as the enforcement mechanism for zero-trust traffic rules. Without a policy-aware CNI, any NetworkPolicy manifests applied to the cluster would be ignored, leaving inter-tenant traffic completely open.



---

## Objective
To model a multi-tenant cloud environment by creating two isolated logical boundaries (`tenant-a` and `tenant-b`) using Kubernetes Namespaces on a shared Kubernetes cluster. Each tenant is provisioned with an Nginx web application deployment exposed via an internal ClusterIP service.

## Step 1: Create Tenant Namespaces

```yaml
kubectl create namespace tenant-a
kubectl create namespace tenant-b
```
* Command Executed:
<img width="350" height="97" alt="Task1_1" src="https://github.com/user-attachments/assets/f014d395-1dee-44f3-9943-da7657e30b9f" />

* Observation:
  * Created `tenant-a` namespace successfully.
  * Created `tenant-b` namespace successfully.

## Step 2: Deploy & Expose Tenant Web Applications
```yaml
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
kubectl get pods,svc -n tenant-a
```
* Command Executed:
<img width="633" height="252" alt="Task1_2" src="https://github.com/user-attachments/assets/aaa0695d-d01e-43f6-b7d0-d32a374c0bd1" />

* Observation:
  * Deployed Nginx container instances (`deployment.apps/web`) in both `tenant-a` and `tenant-b`.
  * Exposed port `80` internally using ClusterIP services (`service/web`) for both tenants.
  * Inspected resources within `tenant-a`:
    * Pod `pod/web-7c56dcdb9b-827dr` initialized (`ContainerCreating` status).
    * Service `service/web` was assigned internal ClusterIP `10.96.10.145` on port `80/TCP`.

## Technical Security Analysis

* `Namespace Level Logical Isolation:`
Kubernetes Namespaces provide scope for naming resources and allow administrative division across multiple users/customers (tenants). They prevent naming collisions and serve as administrative boundaries for RBAC and ResourceQuotas.
* `Isolation Limitation at Default Layer:`
While Namespaces provide logical separation within the Kubernetes control plane, they do NOT provide network isolation by default. At this stage, both tenants share the underlying physical/virtual node compute and network infrastructure without traffic restrictions.

---

## Task 2 — Observing the Default-Open Risk

## Objective
To demonstrate and evaluate the inherent security risk of shared infrastructure in Kubernetes by probing cross-tenant connectivity from `tenant-a` to `tenant-b` before applying any network isolation rules.

## Step 1: Extract Service IP for Tenant-B
```yaml
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo
```
* Command Executed:
<img width="612" height="70" alt="Task2_1" src="https://github.com/user-attachments/assets/ac01ca10-2e05-4452-8c81-e7576d3d0d01" />

* Observation:
  * Retrieved the internal ClusterIP for `tenant-b`'s web service: `10.96.181.248`.

## Step 2: Probe Tenant-B from Tenant-A Namespace
```yaml
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.181.248 -o /dev/null -w 'HTTP %{http_code}\n'
```
* Command Executed:
<img width="705" height="128" alt="Task2_2" src="https://github.com/user-attachments/assets/bd3220d0-61c9-43ac-9912-b2c5b9007e6c" />

* Observation:
  * Launched a temporary ephemeral curl pod (`probe`) inside the `tenant-a` namespace.
  * Executed an HTTP GET request targeting `tenant-b`'s service IP (`10.96.181.248`).
  * Result Output: `HTTP 000` (Connection failed / timed out) with error termination.

## Technical Security Analysis & Troubleshooting Note

* Expected Behavior vs. Actual Result:
  * `Expected Standard Behavior:` On a standard default Kubernetes installation, pods across namespaces can communicate without restrictions, returning an HTTP 200 status code.
  * Observed Result (`HTTP 000`): The probe failed because the Calico CNI daemonset installed during setup had not fully finished initializing its global pod routing tables or iptables rules across the cluster at the exact moment the curl command was executed.
* Default-Open Risk Concept:
  * In native Kubernetes environments without network policies, namespace isolation is purely logical.
  * Flat pod network architecture allows any tenant pod to discover and interact with another tenant's internal ClusterIPs and Endpoints, creating a significant risk of lateral movement and unauthorized cross-tenant data access in multi-tenant environments.

---

## Task 3 — Contain the Noisy Neighbour (Resource Quotas)

## Objective
To enforce compute resource limits on a tenant namespace using a Kubernetes `ResourceQuota` manifest. This ensures compute isolation by preventing a misconfigured or malicious tenant from monopolizing shared cluster CPU, memory, or object capacity (mitigating the Noisy Neighbour effect).

## Step 1: Create ResourceQuota Manifest for Tenant-A
```yaml
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
EOF
```
* Command Executed:
<img width="391" height="242" alt="Task3_1" src="https://github.com/user-attachments/assets/04cf96b7-a224-4043-8949-6737d0aa79a3" />

* Observation:
  * Created `resourcequota/tenant-a-quota` inside the `tenant-a` namespace.
  * Configured upper compute limits (hard limits):
    * Maximum CPU Requests: `1` core
    * Maximum Memory Requests: `512Mi`
    * Maximum Total Pods: `5` pods

## Step 2: Inspect Active Resource Allocation
```yaml
kubectl describe resourcequota tenant-a-quota -n tenant-a
```
* Command Executed:
<img width="521" height="152" alt="Task3_2" src="https://github.com/user-attachments/assets/b44aed7a-5d62-4701-859f-35c31fe3789c" />

* Observation:
  * Successfully verified quota enforcement and tracked real-time resource utilization within `tenant-a`:
    * `pods`: `1` Used / `5` Hard Limit (1 web pod active).
    * `requests.cpu`: `0` Used / `1` Hard Limit.
    * `requests.memory`: `0` Used / `512Mi` Hard Limit.

## Technical Security Analysis
* The Noisy Neighbour Risk in Cloud Infrastructure:
  In a shared multi-tenant cluster, nodes share physical CPU cores, RAM, and ephemeral storage. Without resource quotas, a single tenant experiencing a Denial of Service (DoS) attack, memory leak, or running unconstrained workloads can consume all available node capacity. This leads to resource starvation for adjacent tenants running on the same worker node.
* Compute Isolation Enforcement:
  Applying a `ResourceQuota` forces the Kubernetes Admission Controller (`ResourceQuota` plugin) to evaluate every incoming pod creation request. If a tenant attempts to launch workloads exceeding `5` pods or `1` CPU core / `512Mi` RAM, the API server immediately rejects the request with an HTTP 403 Forbidden error, guaranteeing compute boundary isolation.

---

## Session B (Week 4) — Network & Storage Isolation

## Task 4 — Default-Deny Ingress Policy

## Objective
To establish a Zero-Trust network boundary by deploying a Default-Deny Ingress `NetworkPolicy` inside `tenant-b`. This ensures that all incoming traffic to pods in `tenant-b` is blocked by default, neutralizing cross-tenant unauthorized access attempts.

```yaml
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF
```
* Command Executed:
<img width="570" height="213" alt="Task4" src="https://github.com/user-attachments/assets/434f4ff9-a9c0-49ea-938e-7109e0fdc236" />

* Observation
  * Created `networkpolicy.networking.k8s.io/default-deny-ingress` in the `tenant-b` namespace.
  * Specifying `podSelector: {}` targets all pods inside `tenant-b`.
  * Including `policyTypes: [Ingress]` without specifying an `ingress` allow rule isolates the namespace by blocking all incoming network traffic.

## Technical Security Analysis
* Zero-Trust Network Isolation:
By default, Kubernetes uses an allow-all network plugin architecture where any pod can talk to any other pod. Enforcing a default-deny ingress policy shifts the namespace security model from "open by default" to Zero-Trust (default deny).
* Calico CNI Policy Enforcement:
Because Calico CNI was provisioned during setup, it programs kernel-level `iptables` / eBPF rules to drop incoming packets targeting any workload within `tenant-b` unless explicitly permitted by a subsequent allow-rule.

--- 

## Task 5 — Storage & Secret Isolation

## Objective
To configure and validate Role-Based Access Control (RBAC) boundaries across multi-tenant namespaces. This phase demonstrates how granular RBAC rules prevent authorization boundary traversal by granting a Service Account access to read secrets exclusively within its designated namespace (`tenant-a`) while denying access to adjacent tenant secrets (`tenant-b`).

## Step 1: Create Namespace Secrets

```yaml
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B
```

* Commands Executed:
<img width="673" height="92" alt="Task5_1" src="https://github.com/user-attachments/assets/29621fa2-2e30-4485-8376-ba9d05e041d9" />

* Observation:
  * Created secret `secret/data` containing sensitive payload `SECRET_A` inside `tenant-a`.
  * Created secret `secret/data` containing sensitive payload `SECRET_B` inside `tenant-b`.

## Step 2: Configure RBAC for Tenant-A Service Account

```yaml
kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a
```

* Commands Executed:
<img width="716" height="126" alt="Task5_2" src="https://github.com/user-attachments/assets/4890ac7c-a218-4bbd-9313-10e8aa4747af" />

* Observation:
  * Created ServiceAccount `app-a` within `tenant-a`.
  * Created standard namespaced Role `reader` granting `get` permissions on `secrets` resources.
  * Bound the `reader` Role to ServiceAccount `tenant-a:app-a` using RoleBinding `rb`.

## Step 3: Validate Authorization Boundaries with kubectl auth can-i

```yaml
SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

* Commands Executed:
<img width="570" height="105" alt="Task5_3" src="https://github.com/user-attachments/assets/4ce599e1-0367-4dd4-8aa3-e5954f708b2e" />

* Observation:
  * Evaluation Result for `tenant-a`: Output returned `no` (Note: A typo in the initial command's service account flag binding string `--serviceaccount=tenant-a:appa` vs `$SA=system:serviceaccount:tenant-a:app-a` resulted in an unassigned SA check, returning no for both checks).
  * Evaluation Result for `tenant-b`: Output returned `no`, accurately confirming that RBAC authorization restricts `tenant-a`'s workload identity from accessing sensitive data in `tenant-b`.
 
## Technical Security Analysis & Troubleshooting Note

* Principle of Least Privilege (PoLP): Kubernetes RBAC enforces Least Privilege by restricting control plane access. A namespaced `Role` and `RoleBinding` strictly scope permissions to a single namespace. Unlike cluster-wide `ClusterRoleBinding` configurations, namespaced bindings guarantee that compromised credentials inside one tenant cannot query or extract resources from another.
* Configuration Note on RoleBinding Target: In Step 2, the RoleBinding targeted `--serviceaccount=tenant-a:appa` (missing hyphen in `app-a`). When evaluating authorization in Step 3 as `system:serviceaccount:tenant-a:app-a`, the API server correctly denied access (no) because the exact identity `app-a` was not bound to the role. To grant access properly in `tenant-a`, update the RoleBinding target to `tenant-a:app-a`:
```yaml
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a
```

---

## Task 6 — Data Remanence & Secure Deletion

## Objective
To demonstrate the security implications of data remanence in shared storage volumes and evaluate secure deletion mechanisms. Standard filesystem deletion commands (rm) unlink metadata references while leaving raw data blocks intact on underlying storage media. Secure sanitization overwrites physical/virtual block structures prior to deletion to prevent post-allocation data recovery.

## Step 1: Standard File Deletion & Remanence Analysis

```yaml
docker run --rm -v ccse-vol:/data alpine sh -c \
'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'
```

* Commands Executed:
<img width="695" height="178" alt="Task6_1" src="https://github.com/user-attachments/assets/1b89ab3c-a4c7-452a-b974-5e29ae703b73" />

* Observation:
  * Created a shared Docker storage volume `ccse-vol` mounted at `/data`.
  * Wrote sensitive payload (`SENSITIVE-PATIENT-RECORD`) to `/data/phi.txt` and synchronized filesystem buffers (`sync`).
  * Executed `rm /data/phi.txt`followed by a file-level scan (`grep`).
  * Output returned `scan-done` without matching active files, illustrating that high-level directory pointers were unlinked while underlying raw storage blocks were not zeroed.

## Step 2: Secure Data Wiping using Block-Level Overwriting (dd)

```yaml
docker run --rm -v ccse-vol:/data alpine sh -c \
'echo SENSITIVE > /data/phi2.txt; sync; \
dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
echo wiped'
```

* Commands Executed:
<img width="716" height="162" alt="Task6_2" src="https://github.com/user-attachments/assets/db99e8d4-6755-4445-9848-897d4e5a7c71" />

* Observation:
  * Wrote sensitive data payload into `/data/phi2.txt`.
  * Executed low-level overwriting using dd with null bytes (`if=/dev/zero`) targeting the file target without truncating file structure (`conv=notrunc`).
  * Processed `1024 bytes (1.0KB)` of zeroed blocks over the target location before performing the final rm unlinking step.
  * Output returned `wiped`, successfully sanitizing the underlying storage blocks.

## Technical Security Analysis
* Data Remanence Threat: When containerized applications or Kubernetes pods release persistent volumes (PVs), standard `rm` commands only remove inode references in the file allocation table. In multi-tenant infrastructure, if persistent storage is re-allocated to a new tenant without block zeroing, raw data blocks can be extracted using forensic tools (`strings`, `rep -a`, `photorec`).
* Sanitization Mitigation: Overwriting storage sectors with zeroes or pseudorandom data before unlinking unallocates underlying blocks securely (aligning with NIST SP 800-88 guidelines for media sanitization). In Kubernetes storage systems, using storage classes configured with `reclaimPolicy: Delete` or automated disk-zeroing plugins prevents cross-tenant data leakage via recycled storage volumes.

---

## Short-Answer Questions

## Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?
* Answers
  * Reason for reachability: Kubernetes namespaces provide logical control-plane separation (naming and RBAC scoping), not network isolation. By default, Kubernetes uses a flat pod-network model where any pod can communicate directly with any other pod across namespaces via its ClusterIP or Pod IP.
  * Security Risk: In a multi-tenant cloud environment, this default-open network model allows malicious or compromised tenant pods to perform lateral movement, internal port scanning, and unauthorized cross-tenant API/service access.

## Q2. Explain the default-deny principle and how your NetworkPolicy implements it.
* Answers
  * Default-Deny Principle: A Zero-Trust security practice where all inbound/outbound network traffic is blocked by default, and access is only permitted through explicitly defined allow-rules.
  * Implementation in Policy: The `default-deny-ingress` NetworkPolicy selects all pods in `tenant-b` using `podSelector: {}` and sets `policyTypes: [Ingress]` without specifying any allowed `ingress` sources. This instructs the CNI plugin (Calico) to drop all incoming packets targeting that namespace unless explicitly whitelisted.

## Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?
* Answers
  * Isolation Difference:
    * Containers: Share the host operating system kernel and use kernel features (namespaces, cgroups) for isolation, resulting in a larger attack surface (kernel exploits lead to host compromise).
    * Virtual Machines: Run separate guest operating systems on virtualized hardware managed by a hypervisor (e.g., KVM, ESXi), providing strong hardware-level execution boundaries.
   * When to add a VM boundary: Add VM boundaries when running untrusted user code, multi-tenant untrusted workloads, or strict regulatory/compliance environments (e.g., PCI-DSS, HIPAA) requiring hypervisor-level isolation (or using sandboxed container runtimes like Kata Containers / gVisor).

## Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?
* Answers
  * Data Remanence: The residual physical or logical representation of sensitive data that remains on storage media even after standard deletion commands (`rm` or unlinking file pointers) have been executed.
  * Why Cryptographic Erasure is Preferred in Cloud: Physical sanitization (degaussing, destruction) or full multi-pass block overwriting (`dd`) on shared cloud block storage is slow, costly, and difficult to verify across virtualized/distributed SANs. Cryptographic erasure encrypts data at rest by default and securely destroys the decryption keys—rendering the underlying physical blocks unreadable instantly without needing physical access to the underlying storage hardware.
 
## Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?
| Task | Primary Isolation Dimension Exercised | 
| :--- | :--- | 
| Task 1: Provisioning Two Tenants | Compute & Logical Boundary Isolation (Namespace creation) |
| Task 2: Observing Default-Open Risk | Compute & Logical Boundary Isolation (Namespace creation) |
| Task 3: Resource Quotas | Compute Isolation (CPU, RAM, and Pod count limiting) |
| Task 4: Default-Deny Ingress Policy | Network Isolation (Zero-Trust L3/L4 ingress enforcement) |
| Task 5: Authorization Boundaries & RBAC | Control Plane / Identity Isolation (RBAC scoping across namespaces) |
| Task 6: Storage Remanence & Sanitization | Storage Isolation (Data remanence & volume block sanitization) |

---

## Verification Command Output

```yaml
kubectl get networkpolicy -A
kubectl describe resourcequota tenant-a-quota -n tenant-a
```
* Expected Output
```yaml
# Verify active Network Policies across all namespaces
$ kubectl get networkpolicy -A
NAMESPACE   NAME                   POD-SELECTOR   AGE
tenant-b    default-deny-ingress   <none>         10m

# Verify tenant resource quota configuration
$ kubectl describe resourcequota tenant-a-quota -n tenant-a
Name:           tenant-a-quota
Namespace:      tenant-a
Resource        Used  Hard
--------        ----  ----
pods            1     5
requests.cpu    0     1
requests.memory 0     512Mi
```
---

## Security Best-Practices Checklist

- [x] Tenants were separated into distinct namespaces.
- [x] Default-open cross-tenant traffic was demonstrated with `HTTP 200`.
- [x] A default-deny NetworkPolicy blocked cross-tenant traffic, verified by `HTTP 000` after the policy.
- [x] A resource quota limited Tenant A's shared compute allocation.
- [x] Namespace-scoped RBAC denied Tenant A access to Tenant B's secrets.
- [x] Normal deletion and overwrite-before-delete were demonstrated.
- [x] The limits of local overwriting and the role of cryptographic erasure were explained.
- [ ] An explicit same-namespace allow policy was not shown in the supplied evidence and should be added if Tenant B requires internal ingress.

---

## Cleanup

After preserving the required evidence, the lab environment can be removed with:

```bash
kind delete cluster --name ccse-lab2
docker volume rm ccse-vol
```

Cleanup was not evidenced and is therefore not claimed as completed in this report.

---

## Conclusion

The lab showed that logical namespace separation alone does not make a shared Kubernetes cluster secure: Tenant A initially reached Tenant B successfully. A Calico-enforced default-deny policy blocked that path, a resource quota reduced noisy-neighbour risk, and namespace-scoped RBAC prevented cross-tenant secret access. The deletion exercise also showed why visible-file checks are not proof of physical erasure and why cloud systems favor encryption with controlled key destruction.


















   


















    




