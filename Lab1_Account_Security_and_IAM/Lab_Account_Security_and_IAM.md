# Lab 1: Cloud Account Security, Identity & Access Management (IAM)

* **Course Code:** IKB42603 Cloud Computing Security Essentials
* **Student Name:** Sharif Ammar Izzuddin Bin Sharif Yusri
* **Student ID:** 52215124783
* **Lecturer:** Madam Nor Adani Kamal Mohamad Nasir

---

## Executive Summary
This lab demonstrates the practical application of identity governance, the Principle of Least Privilege (PoLP), and Role-Based Access Control (RBAC) across cloud and containerized environments. Using **LocalStack** (AWS API emulator) and **kind** (Kubernetes-in-Docker), fine-grained authorization policies and RBAC controls were configured, tested, and audited.

---

## Technical Environment Setup
* **Operating System:** VMware Workstation Pro (Kali Linux)
* **Docker Engine:** Installed & Running
* **AWS CLI:** v2 (pointed to LocalStack endpoint: `http://localhost:4566`)
* **Kubernetes Tooling:** `kind` cluster and `kubectl`

---

## Session A: Cloud Identity with LocalStack

### One-Time Environment Setup

#### 1. Environment Verification & Startup
Before configuring identity resources, the local cloud environment was initialized using Docker and LocalStack.

**Commands Executed & Code Explanation:**
* `docker --version`
  * **Purpose:** Verifies that Docker Engine is installed and running on the local system.
* `docker run -d --name localstack -p 4566:4566 localstack/localstack`
  * **Purpose:** Spins up a LocalStack container in detached mode (`-d`), binding port `4566` (LocalStack's gateway) to emulate AWS cloud services locally without incurring real cloud costs[cite: 1].
* `curl http://localhost:4566/_localstack/health`
  * **Purpose:** Queries the health check endpoint of LocalStack to confirm that services (such as IAM, S3, STS) are active and ready to accept API calls[cite: 1].

**Execution Screenshot:**
<img width="1077" height="420" alt="image" src="https://github.com/user-attachments/assets/89b07b40-6f2d-40eb-afc1-3e596cf9747e" />



**Result Analysis & Observations:**
* Docker version `28.5.2+dfsg4` was confirmed active.
* Running docker run yielded a Conflict error, indicating that a LocalStack container named /localstack was already created and actively running in the background.
* The curl health check confirmed that LocalStack version 4.4.0 (Community Edition) was online, with key services like sts marked as running and iam marked as available.

---

#### 2. AWS CLI Local Authentication Configuration
To target LocalStack instead of actual AWS endpoints, dummy credentials and an endpoint override were configured.

**Commands Executed & Code Explanation:**
* `aws configure set aws_access_key_id test`
* `aws configure set aws_secret_access_key test`
* `aws configure set region us-east-1`
  * **Purpose:** Sets default AWS credentials and region settings. LocalStack accepts arbitrary credential values for local emulation.
* `aws --endpoint-url=http://localhost:4566 sts get-caller-identity`
  * **Purpose:** Queries the AWS Security Token Service (STS) via LocalStack's endpoint URL to inspect the active operating identity.

**Execution Screenshot:**


<img width="668" height="247" alt="image" src="https://github.com/user-attachments/assets/7dc7e744-204e-4d90-bad8-767be10c255a" />


**Result Analysis & Observations:**

* The query returned `arn:aws:iam::000000000000:root` as the active identity.

* Deliverable Context: This proves that initial operations are currently running under the Root User. Using the root identity for daily administrative tasks poses high risk, establishing the necessity for Task 2 (creating a scoped admin identity).

### Task 1: Mapping the Cloud Identity Landscape
The following table outlines the fundamental building blocks of AWS IAM:

| Concept | AWS Term | Purpose |
| :--- | :--- | :--- |
| **All-powerful owner** | Root User | The initial default account created with complete, unrestricted access to all resources and billing[cite: 1]. Should only be used for initial setup[cite: 1]. |
| **Human/app identity** | IAM User | An identity created within AWS that represents a specific person or application requiring long-term interaction with AWS services[cite: 1]. |
| **Permission bundle** | IAM Policy | A JSON document that explicitly defines granted permissions (actions allowed or denied on specific resources)[cite: 1]. |
| **Collection of users** | IAM Group | A collection of IAM users used to manage and assign consistent permissions to multiple users simultaneously[cite: 1]. |
| **Temporary identity** | IAM Role | An identity with specific permissions that can be assumed temporarily by users, applications, or AWS services without using permanent credentials[cite: 1]. |

---

### Task 2: Create a Least-Privilege Admin
To eliminate direct reliance on the default all-powerful root user, a dedicated administrator identity (CloudAdmin_Ammar) was created. Following cloud identity security best practices, administrative privileges were granted by assigning the user to a managed group (Admins) rather than attaching policies directly to the individual user.

* Create Administrative Group & Attach Managed Policy: 
<img width="527" height="238" alt="image" src="https://github.com/user-attachments/assets/276606fe-c4df-4273-bd3e-b3f9e5e832bf" />

Explanation 
* `EP='--endpoint-url=http://localhost:4566'`: Defines a shell variable pointing AWS CLI commands to the local LocalStack instance instead of production AWS endpoints.
* `iam create-group --group-name Admins`: Creates an IAM group named Admins to aggregate administrative permissions.
* `iam attach-group-policy ... AdministratorAccess`: Attaches AWS's pre-defined `AdministratorAccess` policy to the `Admins` group. This grants full access to AWS services and resources to any member of the group.

* Create Scoped Admin User:
 <img width="492" height="42" alt="image" src="https://github.com/user-attachments/assets/c799e6f1-4614-4a85-b6f7-937d70df4ae4" />


  Explanation
  * `iam create-user --user-name CloudAdmin_Ammar`: Provisions an individual IAM user identity named CloudAdmin_Ammar for daily administrative duties.

Execution Screenshot:

<img width="545" height="157" alt="image" src="https://github.com/user-attachments/assets/da0db70d-a067-476c-b8bd-b2ab0b80140c" />

  Explanation
  * The IAM service successfully created the user entity with unique ID `qt9gbh4ibpmtjyans3d6` and Amazon Resource Name (ARN) `arn:aws:iam::000000000000:user/CloudAdmin_Ammar`.

* Create Scoped Admin User:
  
<img width="540" height="102" alt="image" src="https://github.com/user-attachments/assets/1285fa06-f0c8-471c-a378-3c01a1b49014" />

* `iam add-user-to-group`: Adds `CloudAdmin_Ammar` to the `Admins` group. Permissions flow implicitly through group membership.
* `iam get-group`: Queries the `Admins` group to verify that the membership was registered correctly.

Execution Screenshot:

<img width="596" height="296" alt="image" src="https://github.com/user-attachments/assets/7050cb81-4367-4e56-be79-4e987ce5ac6f" />

* Security & Verification Context: The output confirms that `CloudAdmin_Ammar` is listed inside the `Users` array of the `Admins` group (`GroupId: xhy3fk7joddjn16kexk4`)
* This structure adheres to central access governance: if administrative privileges need to be modified or revoked, updating the `Admins` group policy automatically updates all contained users without modifying individual account configurations.

---

### Task 3: Enforce Least Privilege with a Scoped Policy
A read-only user (`Analyst_[YOURNAME]`) was created and granted only the `AmazonS3ReadOnlyAccess` policy.

### Commands Executed & Code Explanation

#### 1. Create Read-Only IAM User

<img width="632" height="195" alt="image" src="https://github.com/user-attachments/assets/2fc57202-4660-40fe-8c7c-c4c969b65990" />

Explanation
* `iam create-user`: Provisions an individual IAM user account named `Analyst_Haziq` for analyst/non-administrative tasks.

#### 2. Attach Scoped Policy & Verify Permissions

<img width="606" height="100" alt="image" src="https://github.com/user-attachments/assets/53e2dc59-bcdb-4a16-98e7-9bea85f4cd01" />

Explanation
* `iam attach-user-policy`: Directly attaches the managed policy `AmazonS3ReadOnlyAccess` to `Analyst_Haziq`. This restricts authorization to read actions (`s3:Get*, s3:List*`) specifically on S3 services.
* `iam list-attached-user-policies`: Audits and lists all managed policies attached to the specified user account to verify effective permissions.

Execution Screenshot:

<img width="612" height="142" alt="image" src="https://github.com/user-attachments/assets/4c0b9ea3-2d86-4950-b21c-c23fe724f792" />

Security Explanation & Result Analysis
Result Verification:
* The output of `iam list-attached-user-policies` confirms that `Analyst_Haziq` possesses only one explicitly attached policy: `AmazonS3ReadOnlyAccess `(`arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess`).

Security Explanation: Blast-Radius Reduction (Stolen Credential Analysis)
* Restriction to Read-Only Actions: An attacker gaining access to `Analyst_Haziq` cannot modify, overwrite, or delete existing S3 buckets or objects. They are completely blocked from executing destructive actions.
* Resource Isolation: The policy is scoped exclusively to Amazon S3. An attacker cannot access or tamper with other cloud services such as EC2, DynamoDB, IAM, or CloudTrail.
* Blast-Radius Containment:
By adhering to the Principle of Least Privilege (PoLP), the "blast radius" (the extent of damage an attacker can inflict during a security breach) is minimized. While a compromised Admin account results in total cloud takeover, a compromised `Analyst_Haziq` account limits the incident purely to potential data disclosure within S3, protecting overall system integrity and preventing privilege escalation.


---

### Task 4: Credential Hygiene & Access Keys
Access keys were created for programmatic access and subsequently rotated (deactivated) to demonstrate credential management hygiene.

### Commands Executed & Code Explanation
#### 1. Create an Access Key for the Analyst

<img width="691" height="53" alt="image" src="https://github.com/user-attachments/assets/35afbe6c-2916-4180-8842-f3a825e1194c" />

* `iam create-access-key`: Generates a new programmatic access key pair (`AccessKeyId` and `SecretAccessKey`) for the specified user (`Analyst_Haziq`).

Execution Screenshot:

<img width="606" height="192" alt="image" src="https://github.com/user-attachments/assets/3b76d537-929b-451d-8628-5d224657c216" />

### 2. List Access Keys (Audit Status)

<img width="623" height="55" alt="image" src="https://github.com/user-attachments/assets/47c21ed1-35d3-44a9-b954-da32d4c4cc81" />

* `iam list-access-keys`: Retrieves metadata for all access keys associated with the user, allowing security teams to audit active versus inactive keys.

Execution Screenshots:

<img width="482" height="133" alt="image" src="https://github.com/user-attachments/assets/ed6656af-3421-404d-8fd1-9d12c3147e7b" />

### 3. Rotate and Deactivate the Old Key

<img width="508" height="61" alt="Screenshot 2026-08-03 005802" src="https://github.com/user-attachments/assets/9479eff3-5ee1-4930-b7ac-ca719b128a5a" />


<img width="487" height="43" alt="image" src="https://github.com/user-attachments/assets/19398d7d-f35f-4ea1-ae48-53b73b7b402b" />

* `iam update-access-key`: Modifies the state of a specific access key. Changing the status to `Inactive` immediately revokes its capability to authenticate API requests without completely deleting the key record.

Execution Screenshots:

<img width="472" height="133" alt="Screenshot 2026-08-03 005856" src="https://github.com/user-attachments/assets/14f17e54-8ed3-4fba-a7cb-d0305cf244b6" />

Security Explanation & Risks of Long-Lived Keys
Result Verification:
* The output confirms that the access key (`LKIAQAAAAAAABRO26ZHA`) status has successfully transitioned from `Active` to `Inactive`, terminating programmatic access for that specific key.

Risks Associated with Long-Lived Keys:
* Extended Exposure Window: Keys that remain active indefinitely ("long-lived keys") provide a persistent attack vector. If a secret access key is accidentally committed to a public repository, logged improperly, or leaked via malware, an attacker retains indefinite access until the key is manually discovered and revoked.
* Lack of Automated Rotation: Unlike temporary security credentials generated via IAM roles (which expire automatically within hours), static access keys do not expire on their own. This violates the principle of least privilege over time as forgotten or orphaned keys accumulate.
* Mitigation via Key Rotation: Regular credential rotation (creating a new key, updating applications to use it, deactivating the old key, and finally deleting it) limits the window of opportunity for attackers and ensures better compliance and security posture across cloud infrastructure.


---

## Session B: Enforced Access Control with Kubernetes RBAC

# Session B (Week 2) — Enforced Access Control with Kubernetes RBAC

## Overview
While LocalStack allows learning IAM concepts and API structures, it does not fully enforce authorization boundaries. Kubernetes Role-Based Access Control (RBAC) provides real-time policy enforcement. In this session, access control rules actively block unauthorized API calls to demonstrate fine-grained security enforcement in action.

---

## Setup — Create a Local Kubernetes Cluster

### Commands Executed & Code Explanation

#### 1. Provision Local Cluster with `kind`

<img width="397" height="37" alt="image" src="https://github.com/user-attachments/assets/dd77609f-1f1c-43ee-974a-d2699ecd6244" />


* `kind create cluster`: Spuns up a local Kubernetes cluster using Docker containers as nodes (`kind` = Kubernetes in Docker).
* `--name ccse-lab1`: Specifies a custom context and cluster identifier named `ccse-lab1`.

### 2. Confirm Cluster Status & Node Readiness

<img width="430" height="57" alt="image" src="https://github.com/user-attachments/assets/bc64a597-611d-4232-93cf-e3b85adfd67d" />

* `kubectl cluster-info`: Displays the control plane IP/port endpoints and active core service URLs (e.g., CoreDNS) to verify Kubernetes API accessibility.
* `kubectl get nodes`: Lists all worker/control-plane nodes in the cluster along with their status, roles, age, and Kubernetes version.

Execution Screenshot:

<img width="877" height="415" alt="Screenshot 2026-08-03 003541" src="https://github.com/user-attachments/assets/27a1ce82-1629-46a4-a42c-a579aca84015" />

Result Analysis:
* Successful Initialization: The `kind` tool built the single-node control plane running Kubernetes `v1.30.0`.
* Context Configuration: The local `kubeconfig` was automatically updated to set `kind-ccse-lab1` as the active context, routing all subsequent `kubectl` commands to this local cluster environment.

---

## Task 5: Separate Environments with Namespaces

### Overview
Kubernetes Namespaces provide logical isolation within a shared physical cluster. Creating dedicated namespaces for development (`dev`) and production (`prod`) establishes security boundaries that prevent cross-environment access and accidental configuration overwrites.

---

### Commands Executed & Code Explanation

<img width="403" height="66" alt="image" src="https://github.com/user-attachments/assets/1526b4d8-ed46-4082-b97b-168fa11866e6" />

* `kubectl create namespace dev`: Provisions an isolated logical boundary named dev for development workloads.
* `kubectl create namespace prod`: Provisions an isolated logical boundary named prod for production workloads.
* `kubectl get namespaces`: Lists all active namespaces within the cluster to confirm successful provisioning.

Execution Screenshot:

<img width="405" height="242" alt="Screenshot 2026-08-03 003615" src="https://github.com/user-attachments/assets/31bd68ff-6bf7-4d36-a704-1137c3f00400" />

### Task 6: Define a Role and Bind It (Least Privilege)

### Overview
Kubernetes Role-Based Access Control (RBAC) regulates access based on the roles of individual users within an enterprise. In this task, a fine-grained RBAC rule is constructed: a scoped Role defining read-only permissions on pods is bound via a RoleBinding to a developer ServiceAccount inside the `dev` namespace.

### Commands Executed & Code Explanation

1. Create Developer Service Account

<img width="443" height="37" alt="image" src="https://github.com/user-attachments/assets/f67ac44b-5156-482e-9e3e-03608bdb3dd8" />

* create serviceaccount dev-user -n dev: Provisions an identity (dev-user) scoped specifically to the dev namespace to represent the developer identity.

2. Define Scoped Role

<img width="383" height="56" alt="image" src="https://github.com/user-attachments/assets/ccc7aac4-7c8c-4f02-9630-30c506c5be58" />

* `create role pod-reader -n dev`: Creates a namespace-scoped RBAC Role named `pod-reader` in `dev`.
* `--verb=get,list,watch`: Restricts actions strictly to read operations.
* `--resource=pods`: Limits the API target exclusively to Pod resources, denying access to secrets, deployments, or nodes.

3. Bind Role to Service Account

<img width="470" height="47" alt="image" src="https://github.com/user-attachments/assets/29e841a2-fe76-4387-b74d-6e094f4d8dec" />

* `create rolebinding dev-user-binding -n dev`: Maps the pod-reader role permissions directly to the dev-user service account (`ev:dev-user`) inside the `dev` namespace.

Execution Screenshot:

<img width="583" height="230" alt="Screenshot 2026-08-03 003706" src="https://github.com/user-attachments/assets/fc9d436a-6911-455a-b586-67445ecfb8cb" />

Result Analysis & Security Context:
* Role-Based Access Control Architecture: RBAC decouples permissions (defined in the `pod-reader` Role) from identities (represented by the `dev-user` ServiceAccount). The `RoleBinding` acts as the explicit bridge granting those specific permissions to that identity.
* Enforcing Least Privilege: By limiting verbs to `get`, `list`, and `watch`on `pods`, the `dev-user` cannot modify existing workloads, delete pods, or create new deployments. Furthermore, because a `Role` is namespaced, these permissions are completely ineffective outside the `dev` namespace.

---

### Task 7: Authorization Testing (`kubectl auth can-i`)
Access control boundaries were tested using the `kubectl auth can-i` command representing `dev-user`.

### Commands Executed & Code Explanation

#### Set Service Account Variable & Perform Authorization Checks

<img width="510" height="247" alt="Screenshot 2026-08-03 003828" src="https://github.com/user-attachments/assets/10cf7422-c30c-48a4-b658-5dfd5140ce10" />

* `SA=system:serviceaccount:dev:dev-user`: Defines an environment variable pointing to the fully qualified Kubernetes Service Account identifier for `dev-user` in the `dev` namespace.
* `kubectl auth can-i`: Queries the Kubernetes SelfSubjectAccessReview API to determine whether the specified impersonated entity (`--as=$SA`) can perform a given action.
* `--as=$SA`: Impersonates the `dev-user` service account to test authorization without switching physical contexts.

### Security Evaluation & Verification Matrix

| Test Scenario | Command Executed | Target Namespace | Expected | Result | Security Context|
| :--- | :--- | :--- | :--- | :--- | :--- |
  | `Read Pods in Dev` | `kubectl auth can-i list pods` | `dev` | **YES** | **YES** | Explicitly permitted by the `pod-reader` Role (`verbs: [get, list, watch]`). |
| `Delete Pods in Dev` | `kubectl auth can-i delete pods` | `dev` | **NO** | **NO** | Blocked because `delete` verb is not defined in the `pod-reader` Role (Principle of Least Privilege). |
| `Read Pods in Prod` | `kubectl auth can-i list pods` | `prod` | **NO** | **NO** | Blocked because the `RoleBinding` is restricted strictly to the `dev` namespace (Namespace Isolation). |



Security Analysis & Conclusion:
* Real-time Enforcement Proven: Unlike mock IAM tools, Kubernetes API Server actively evaluated and rejected unauthorized requests (`delete` verb and cross-namespace access to `prod`).
* Namespace Isolation: Confirms that namespaced RBAC roles cannot leak permissions into other namespaces (`prod`), ensuring strong multi-tenant security boundaries inside the cluster.

## Short-Answer Questions

**Q1. Why is attaching policies to groups better than attaching them directly to users?**

Attaching a policy to a group centralises permission management: a single policy change on the group propagates automatically to every member, rather than requiring the same change to be repeated on each individual user. This reduces the risk of inconsistent or drifted permissions across identities, makes access easier to audit (permissions can be reasoned about at the group level rather than user-by-user), and simplifies onboarding/offboarding, since adding or removing a user from a group instantly grants or revokes the group's permission set.

**Q2. What is the difference between an IAM User and an IAM Role?**

An IAM User is a persistent identity representing a specific person or application, with its own long-term credentials (a password and/or access keys) that remain valid until explicitly rotated or revoked. An IAM Role, in contrast, has no long-term credentials of its own; it is *assumed* temporarily by a user, application, or AWS service, and grants only short-lived, automatically-expiring security credentials for the duration of that session. Roles are therefore preferred wherever access does not need to persist indefinitely, since there is no long-lived secret that can be leaked or forgotten.

**Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.**

The `Analyst_Haziq` account was deliberately scoped to only the `AmazonS3ReadOnlyAccess` policy - the minimum permission needed for its intended purpose. If this account's credentials were compromised, the attacker's actions would be limited strictly to reading S3 objects: they could not delete or modify data, create or alter IAM identities, provision new resources, or access any other AWS service. This is the essence of blast-radius reduction - the "radius" of possible damage from a compromised identity is bounded by exactly the permissions that identity was given, which is why the Analyst account was never granted anything beyond what its role actually required.

**Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?**

A Role is a namespaced object that defines *what* actions are permitted - a set of verbs (e.g. `get`, `list`, `watch`) on a set of resources (e.g. `pods`) - but does not, by itself, grant that permission to anyone. A RoleBinding is the object that actually grants a Role to a specific subject (a user, group, or ServiceAccount) within a namespace. A Role with no RoleBinding pointing to it grants no access at all; both objects must exist together for access to take effect.

**Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?**

The `dev-user-binding` RoleBinding was created only in the `dev` namespace, binding `pod-reader` solely to that scope. Kubernetes RBAC is namespace-scoped and denies by default: without an equivalent Role and RoleBinding explicitly created inside `prod`, no permissions exist there for that service account, so the request is denied. This demonstrates the principle of **least privilege combined with default-deny authorization** - an identity has no access anywhere except where it has been explicitly granted, so a permission boundary in one environment (`dev`) does not silently extend into another (`prod`), even within the same cluster.

## Security Best-Practices Checklist

- [x] Root user is not used for daily tasks (a dedicated admin identity, `CloudAdmin_Ammar`, was created)
- [x] Permissions are granted via groups/roles, not directly to individual users
- [x] At least one least-privilege (read-only) identity was created and tested (`Analyst_Haziq`)
- [x] Access keys were listed and a rotation (deactivation) was demonstrated
- [x] Kubernetes RBAC blocks an unauthorised action (delete pods, cross-namespace access)

## Conclusion

Lab 1 demonstrated the practical application of least privilege across two distinct layers of a cloud environment. At the AWS identity layer (via LocalStack), root usage was replaced with a dedicated administrator identity managed through a group, and a separately scoped read-only Analyst identity was created and tested, with its access keys rotated to reflect proper credential hygiene. At the container-orchestration layer, Kubernetes RBAC was configured and directly verified using `kubectl auth can-i`, confirming that a developer service account could read pods within its assigned namespace but was correctly denied both a destructive action (`delete`) and cross-namespace access (`prod`). Together, these results confirm that least privilege was enforced - not merely configured - at both the cloud identity and platform levels, satisfying the lab's core learning outcomes.
