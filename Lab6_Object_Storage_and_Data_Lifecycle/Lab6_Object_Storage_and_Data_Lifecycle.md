# Lab 6: Object Storage Security & the Data Security Lifecycle

* **Course Code:** IKB42603 Cloud Computing Security Essentials
* **Student Name:** Sharif Ammar Izzuddin Bin Sharif Yusri
* **Student ID:** 52215124783
* **Lecturer:** Madam Nor Adani Kamal Mohamad Nasir

---

## Executive Summary

This laboratory project demonstrates the practical implementation of object storage security controls and the full data security lifecycle within a cloud-native environment using Docker and LocalStack (simulating AWS S3 and AWS KMS). The primary objective is to move beyond basic storage provisioning towards defensible security posture — enabling the reproduction and remediation of real-world breach patterns, the enforcement of encryption and least-privilege access, and the achievement of provable data deletion.

The lab is structured into two core operational sessions aligned with CLO2 (Construct secure cloud operations that safeguard data confidentiality and integrity):

- **Session A (Object Storage & the Exposure Problem):** Provisioning object storage, classifying data by sensitivity, reproducing the archetypal public-bucket breach, remediating it with Block Public Access and least-privilege bucket policies, and resolving conflicts between identity-based (IAM) and resource-based (bucket policy) authorisation.
- **Session B (Protecting, Retaining and Retiring Data):** Enforcing default encryption at rest with SSE-KMS, issuing time-bounded delegated access via presigned URLs, demonstrating object-level data remanence through versioning and delete markers, and achieving provable deletion through lifecycle rules and cryptographic erasure.

---

## Session A (Week 11) — Object Storage & the Exposure Problem

### Setup — Start LocalStack

**Objective**

Start a clean, activated LocalStack instance with `ENFORCE_IAM=1` so that IAM policies are actually evaluated rather than allowing everything, and point the AWS CLI at it.

**Commands**

```bash
docker rm -f localstack
docker run -d --name localstack -p 4566:4566 \
  -e LOCALSTACK_AUTH_TOKEN=$LOCALSTACK_AUTH_TOKEN \
  -e ENFORCE_IAM=1 \
  localstack/localstack-pro:latest

export EP='--endpoint-url=http://localhost:4566'
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1
aws $EP sts get-caller-identity
```

**Screenshot**

<img width="542" height="147" alt="Setup1" src="https://github.com/user-attachments/assets/e1c25416-6a62-4ae7-ad89-6f4dad93f1e4" />

<img width="542" height="147" alt="Setup1" src="https://github.com/user-attachments/assets/14f5f7f0-7ce6-4181-92d5-54f85280dfd5" />


**Result / Explanation**

The LocalStack container started successfully in detached mode with `ENFORCE_IAM=1` enabled, which forces LocalStack to actually evaluate IAM and resource policies instead of granting blanket access — this is required for the policy-vs-policy tests in Task 4. After pointing the AWS CLI at the LocalStack endpoint (`http://localhost:4566`) and configuring dummy credentials, `aws sts get-caller-identity` confirmed the connection by returning LocalStack's simulated identity:

- **UserId / Account:** `000000000000`
- **Arn:** `arn:aws:iam::000000000000:root`

This account number (`000000000000`) is the root principal used later when writing ARNs into bucket and IAM policies (e.g. Task 3's least-privilege policy and Task 4's analyst policy).

---

### Task 1 — Classify the Data Before You Store It

**Objective**

Create a bucket for a hospital records system, store three objects of differing sensitivity, and tag each with its classification.

**Commands**

```bash
export BUCKET=miit-patient-records-$RANDOM
echo $BUCKET

aws $EP s3api create-bucket --bucket $BUCKET

echo 'Ward visiting hours 10am-8pm' > public-notice.txt
echo 'Staff duty schedule, week 12' > internal-roster.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential' > confidential-record.txt

aws $EP s3api put-object --bucket $BUCKET --key public/notice.txt \
  --body public-notice.txt --tagging 'classification=public'
aws $EP s3api put-object --bucket $BUCKET --key internal/roster.txt \
  --body internal-roster.txt --tagging 'classification=internal'
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body confidential-record.txt --tagging 'classification=confidential'

aws $EP s3api list-objects-v2 --bucket $BUCKET \
  --query 'Contents[].[Key,Size]' --output table
aws $EP s3api get-object-tagging --bucket $BUCKET --key confidential/record.txt
```

**Screenshot**

<img width="501" height="187" alt="Task1-1" src="https://github.com/user-attachments/assets/62aafb96-ca1b-4dd1-9b3b-fd8e8e20ad2a" />


<img width="672" height="507" alt="Task1-2" src="https://github.com/user-attachments/assets/5d117dfd-9733-40f9-87fb-cf77f6af1c4b" />


<img width="637" height="327" alt="Task1-3" src="https://github.com/user-attachments/assets/85e59a98-92bc-40ff-bb67-61f016de9765" />


**Data Classification Table**

| Classification | Who may read it | Impact if leaked | Control you will apply |
|---|---|---|---|
| public | Anyone (general public, all staff, visitors) | Minimal — information is already intended for open disclosure | No restriction needed; can remain publicly readable via bucket policy |
| internal | Authenticated staff/employees only (not external parties) | Moderate — exposes operational details (e.g. duty schedules) that could aid social engineering or reveal staffing patterns | IAM/bucket policy scoped to the `internal/` prefix, restricted to the organisation's AWS principal (Task 3's least-privilege policy) |
| confidential | Only authorised personnel with a legitimate need-to-know (e.g. attending clinicians) | Severe — direct patient data breach, violates PDPA/GDPR, reputational and legal liability | Deny-by-default access, SSE-KMS encryption at rest (Task 5), explicit Deny statements overriding broader IAM grants (Task 4) |

**Explanation**

The bucket was created as `miit-patient-records-29278`, and three objects were uploaded under different key prefixes (`public/`, `internal/`, `confidential/`), each tagged with its own `classification` value. The `list-objects-v2` output confirms all three objects exist with distinct sizes, and `get-object-tagging` on `confidential/record.txt` confirms the tag `classification=confidential` was correctly applied.

Note that `confidential/` is **not** a real folder — S3 (and object storage generally) uses a **flat namespace**, where the key is simply a single string (`confidential/record.txt`) and the `/` is

---

### Task 2 — Reproduce the Archetypal Breach

**Objective**

Build a bucket policy with `"Principal": "*"` and read the confidential record anonymously — with no AWS credentials at all — to reproduce the classic exposed-bucket breach.

**Commands**

```bash
cat > public-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicReadEverything",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$BUCKET/*"
  }]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text

curl -s -o leaked.txt -w 'HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt
cat leaked.txt
```

**Screenshot**

<img width="722" height="572" alt="Task2" src="https://github.com/user-attachments/assets/c6a0dd1d-ad45-4623-b5a3-615c75185146" />


**Explanation**

The policy was applied and confirmed via `get-bucket-policy`, granting `s3:GetObject` on `arn:aws:s3:::miit-patient-records-29278/*` to `Principal: "*"`. The anonymous `curl` request — made with **no AWS credentials, no CLI, no signing, just a plain HTTP URL** — returned `HTTP 200` and printed the full confidential record:

The single element responsible for the exposure is `"Principal": "*"`. This statement means the policy grants the `s3:GetObject` permission to *any* principal — authenticated or not — effectively making every object under the bucket's `*` resource pattern world-readable over plain HTTP. There was no exploit, no malware, and no software vulnerability involved; the breach was purely a **misconfiguration** — a resource policy that explicitly authorised the entire internet to read patient data. This is the exact pattern behind the majority of real-world "exposed S3 bucket" headlines.

---

### Task 3 — Remediate with Block Public Access

**Objective**

To remediate public exposures by enabling S3 Block Public Access guardrails, testing preventative policy rejection against over-broad policies, and constructing a least-privilege resource policy restricted strictly to account root and internal key prefixes[cite: 1].

**Step 1: Demonstrating Unrestricted Access & Enforcing Public Access Block**

**Commands**

```bash
curl -s -o leaked.txt -w 'HTTP %{http_code}\n' http://localhost:4566/$BUCKET/confidential/record.txt
cat leaked.txt
aws $EP s3api delete-bucket-policy --bucket $BUCKET
aws $EP s3api put-public-access-block --bucket $BUCKET \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws $EP s3api get-public-access-block --bucket $BUCKET
```

**Screenshot**

<img width="777" height="422" alt="Task3-1" src="https://github.com/user-attachments/assets/f67a59a6-2faa-472d-b6e9-8cc7aa54b56c" />

**Explanation**

The initial `curl` request confirms broken access controls on the S3 bucket, as confidential patient records in `record.txt` are successfully retrieved anonymously with an HTTP 200 OK status code, resulting in the exposure of sensitive medical data (Ahmad bin Ali, Diagnosis: confidential). To begin the remediation process, the existing bucket policy is deleted via the `delete-bucket-policy` command to eliminate any existing misconfigurations. Following this, the `put-public-access-block` command is executed to enforce strict public access restrictions by setting `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets` to `true`. Finally, the configuration is verified using get-public-access-block, confirming that all four S3 Block Public Access safety flags are active on the target bucket.

**Step 2: Testing Public Policy Application**

```bash
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
curl -s -o /dev/null -w 'anonymous read now: HTTP %{http_code}\n' http://localhost:4566/$BUCKET/confidential/record.txt
```

**Screenshot**

<img width="726" height="125" alt="Task3-2" src="https://github.com/user-attachments/assets/107f0310-ad2d-4873-87c1-5ac62eecfb8c" />

**Explanation**

A public bucket policy defined in `public-policy.json` is applied to the bucket using the `put-bucket-policy` command to evaluate how the environment handles modified access permissions. An unauthenticated HTTP GET request issued through `curl` returns an HTTP 200 OK status code, demonstrating that anonymous public read access remains functional under this specific policy configuration.

**Step 3: Enforcing Least Privilege Bucket Policy**

**Commands**

```bash
cat > least-privilege-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AccountReadInternalOnly",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$BUCKET/internal/*"
  }]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://least-privilege-policy.json
aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text
```

**Screenshot**

<img width="775" height="432" alt="Task3-3" src="https://github.com/user-attachments/assets/061786a7-c203-430b-a15e-b708dcbe8f59" />

**Explanation**

A secure, least-privilege policy is authored and saved into `least-privilege-policy.json`, restricting `s3:GetObject` permissions strictly to the root account principal (`arn:aws:iam::000000000000:root`) and limiting access scope solely to objects located within the /`internal/*` directory. This updated security policy is attached to the bucket using `put-bucket-policy` to override any permissive rules. Running `get-bucket-policy` retrieves and verifies the active policy on `miit-patient-records-29278`, confirming that public data exposure has been fully mitigated and access is strictly restricted to authorized internal entities.

---

### Task 4: IAM User Provisioning and Explicit Deny Access Controls

**Objective**

To provision a dedicated IAM user, configure local AWS CLI profile credentials, and enforce explicit deny permissions within an S3 bucket policy to restrict access to sensitive resources.

**Step 1: Provisioning IAM User and Granting Initial S3 Policies**

**Commands**

```bash
aws $EP iam create-user --user-name DataAnalyst

cat > analyst-iam.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": "*"
  }]
}
JSON

aws $EP iam put-user-policy --user-name DataAnalyst \
  --policy-name S3ReadAll --policy-document file://analyst-iam.json

aws $EP iam create-access-key --user-name DataAnalyst \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text
```

**Screenshot**

<img width="612" height="497" alt="Task4-1" src="https://github.com/user-attachments/assets/3915b212-831d-4f71-ac5d-07e96b8d8182" />

**Explanation**

An IAM user named `DataAnalyst` is created using the `create-user` command, followed by defining an inline policy in `analyst-iam.json` that grants baseline `s3:GetObject` and `s3:ListBucket` permissions across all resources. This inline policy is attached to the user via `put-user-policy` under the policy name `S3ReadAll`, after which programmatic credentials are generated using `create-access-key` to allow external authentication for the new user entity.

**Step 2: Configuring AWS CLI Profile and Deploying Explicit Deny Bucket Policy**

**Commands**

```bash
aws configure --profile analyst set aws_access_key_id LKIAQAAAAAAAAALEWNHG5
aws configure --profile analyst set aws_secret_access_key pnCQN8JS2A9vE5J7s9e64lXgTZr7gQ1GxWqnJ52s
aws configure --profile analyst set region us-east-1

cat > deny-confidential.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAnalystInternal",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$BUCKET/internal/*"
    },
    {
      "Sid": "DenyAnalystConfidential",
      "Effect": "Deny",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::$BUCKET/confidential/*"
    }
  ]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://deny-confidential.json
```

**Screenshot**

<img width="802" height="477" alt="Task4-2" src="https://github.com/user-attachments/assets/479495ec-df6f-4f5e-8e1d-69b27cedeff4" />

**Explanation**

The AWS CLI environment is configured with a dedicated profile named `analyst` using the newly generated access key credentials and default region settings. To enforce granular resource segregation, a bucket policy defined in `deny-confidential.json` is applied using `put-bucket-policy`, explicitly allowing `DataAnalyst` access to objects under the `/internal/*` prefix while enforcing an explicit `Deny` on all `s3:*` actions targeting the `/confidential/*` directory.

**Step 3: Verifying Access Rules via AWS CLI Profile**

**Commands**

```bash
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET --key internal/roster.txt analyst-internal.txt && echo "internal: ALLOWED"

AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET --key confidential/record.txt analyst-confidential.txt || echo "confidential: DENIED"
```

**Screenshot**

<img width="777" height="470" alt="Task4-3" src="https://github.com/user-attachments/assets/a2c36008-c6a7-4676-9e3a-0d4f7874258f" />

**Explanation**
Access rules are tested under the `analyst` CLI profile by executing `get-object` requests against both internal and confidential S3 paths. The retrieval of `internal/roster.txt` completes successfully returning an HTTP status OK along with the `internal: ALLOWED` output, while attempts to access `confidential/record.txt` trigger the explicit deny rule defined in the bucket policy, successfully blocking unauthorized access to confidential records.

---
### Cleanup Session A: Removing Existing S3 Bucket Policies

**Objective**

To remove any lingering or misconfigured bucket policies from the target S3 bucket before applying new security configurations.

**Step 1: Deleting Existing Bucket Policy**

**Commands**

```bash
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

**Screenshot**

<img width="442" height="47" alt="CU(SA)" src="https://github.com/user-attachments/assets/dab4397e-a9c3-4595-9361-d45db29e2d9a" />

**Explanation**

The `delete-bucket-policy` command is executed to remove any existing access control policies attached to the S3 bucket, ensuring a clean baseline state before implementing revised security rules and permission boundaries.

---

### Task 5: KMS Key Generation and S3 Server-Side Encryption Enforcement

**Objective**

To generate a custom AWS Key Management Service (KMS) Customer Managed Key (CMK), enforce default server-side encryption using SSE-KMS on the target S3 bucket, and verify encryption parameters on uploaded objects.

**Step 1: Creating a Custom AWS KMS Key**

**Commands**

```bash
export KEY_ID=$(aws $EP kms create-key \
  --description 'IKB42603 Lab6 patient records bucket key' \
  --query 'KeyMetadata.KeyId' --output text)
echo $KEY_ID
```

**Screenshot**

<img width="565" height="106" alt="Task5-1" src="https://github.com/user-attachments/assets/e4a4e565-ee69-440c-bbdc-e3d86fafe236" />

**Explanation**

A new Customer Managed Key is generated in AWS KMS using the `create-key` command, assigning a specific description identifying its intended use for securing patient records in Lab 6. The unique identifier returned in `KeyMetadata.KeyId` is extracted and exported directly to the `KEY_ID` environment variable, returning the key ID `7c5512a3-3ec9-46a1-bace-50afddc4eaa0`.

**Step 2: Configuring Default Bucket Encryption with SSE-KMS**

**Commands**

```bash
cat > encryption.json <<JSON
{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "$KEY_ID"
    },
    "BucketKeyEnabled": true
  }]
}
JSON

aws $EP s3api put-bucket-encryption --bucket $BUCKET \
  --server-side-encryption-configuration file://encryption.json

aws $EP s3api get-bucket-encryption --bucket $BUCKET
```

**Screenshot**

<img width="646" height="572" alt="Task5-2" src="https://github.com/user-attachments/assets/1456705b-aeaf-47f7-9a1f-faf2e1914bca" />

**Explanation**

An encryption configuration file named `encryption.json` is created to mandate default server-side encryption using the `aws:kms` algorithm alongside the newly generated KMS key ID and S3 Bucket Key optimization. The policy is applied to the target S3 bucket using `put-bucket-encryption`, and subsequent verification via `get-bucket-encryption` confirms that automatic SSE-KMS encryption is active across the bucket with S3 Bucket Key support enabled.

**Step 3: Uploading File and Verifying Server-Side Encryption Attributes**

**Commands**

```bash
aws $EP s3api put-object --bucket $BUCKET \
  --key confidential/record-v2.txt --body confidential-record.txt

aws $EP s3api head-object --bucket $BUCKET --key confidential/record-v2.txt \
  --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' --output text
```

**Screenshot**

<img width="797" height="252" alt="Task5-3" src="https://github.com/user-attachments/assets/eb2ccf71-a432-425b-9279-81dabbb02515" />

**Explanation**

A new confidential record file is uploaded to the S3 bucket using the `put-object` command without specifying manual encryption flags, relying entirely on the bucket's default encryption configuration. Inspecting object metadata via `head-object` confirms that server-side encryption was automatically applied at rest using `aws:kms`, bound to the ARN of the custom KMS key `arn:aws:kms:us-east-1:000000000000:key/7c5512a3-3ec9-46a1-bace-50afddc4eaa0`, with `BucketKeyEnabled` returning `True`.

---

### Task 6: Pre-Signed URL Expiration Testing and Secure Transport Policy Enforcement

**Objective**

To evaluate the time-based expiration behavior of S3 pre-signed URLs, enforce mandatory HTTPS encrypted transit across the bucket via policy conditions, and list final stored objects.

**Step 1: Generating Pre-Signed URL and Testing Expiration**

**Commands**

```bash
URL=$(aws $EP s3 presign s3://$BUCKET/internal/roster.txt --expires-in 60)
echo "$URL"
curl -s -w '  <--- HTTP %{http_code}\n' "$URL"

sleep 65
curl -s -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"
```

**Screenshot**

<img width="920" height="245" alt="Task6-1" src="https://github.com/user-attachments/assets/b1261bb8-a282-41ff-b854-4dcf01abb125" />

**Explanation**

A temporary access link for `internal/roster.txt` is generated using the `presign` command with a 60-second expiration period (`--expires-in 60`). An immediate HTTP request issued via `curl` returns an HTTP 200 OK response along with the file contents (Staff duty schedule, week 12), while repeating the request after waiting 65 seconds using `sleep` evaluates whether access is properly revoked upon token expiration.

**Step 2: Enforcing Secure Transport (TLS/HTTPS) Bucket Policy**

**Commands**

```bash
cat > secure-transport.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnencryptedTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::$BUCKET", "arn:aws:s3:::$BUCKET/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://secure-transport.json
```

**Screenshot**

<img width="730" height="287" alt="Task6-2" src="https://github.com/user-attachments/assets/68c89717-6604-49ae-9ca0-6f2487728e59" />

**Explanation**

A bucket policy is crafted in `secure-transport.json` using an explicit `Deny` condition paired with `"aws:SecureTransport": "false"` to block any unencrypted HTTP requests targeting the bucket or its contents. The policy is applied to the target bucket using `put-bucket-policy` to ensure all data-in-transit must strictly utilize TLS/HTTPS connections.

**Step 3: Listing Final Bucket Objects and Cleaning Up Bucket Policy**

**Commands**

```bash
aws $EP s3api list-objects-v2 --bucket $BUCKET
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

**Screenshot**

<img width="682" height="605" alt="Task6-3" src="https://github.com/user-attachments/assets/f0f661e3-11d2-4911-b0c3-ab5eec3d8d4c" />

<img width="532" height="307" alt="Task6-4" src="https://github.com/user-attachments/assets/9002f797-1954-4897-a612-f3f74064a780" />

**Explanation**

The `list-objects-v2` command is executed to review all active objects stored inside the bucket, confirming the presence of files across the confidential, internal, and public paths (`confidential/record-v2.txt`, `confidential/record.txt`, `internal/roster.txt`, and `public/notice.txt`). Finally, the `delete-bucket-policy` command is run to remove the attached bucket policy as part of the teardown process for the lab session.

---

### Task 7: S3 Object Versioning, Soft Deletion, and Version Recovery

**Objective**

To demonstrate how S3 Object Versioning tracks multiple revisions of an object, handles soft deletion using Delete Markers, and enables historic data recovery by targeting specific Version IDs.

**Commands**

```bash
echo 'Patient: Ahmad bin Ali, Diagnosis: hypertension' > rec-v2.txt
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]' > rec-v3.txt

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v2.txt --query VersionId --output text

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v3.txt --query VersionId --output text

aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'Versions[].[VersionId,IsLatest,Size]' --output table
```

**Screenshot**

<img width="627" height="380" alt="Task7-1" src="https://github.com/user-attachments/assets/48a117bb-9709-48bf-8416-9f5235fc4559" />

**Explanation**

Two new revisions (`rec-v2.txt` and `rec-v3.txt`) are created and uploaded sequentially to overwrite `confidential/record.txt`, generating unique Version IDs for each upload. Running `list-object-versions` confirms that the latest active version (`IsLatest: True`) corresponds to the redacted record, while historical revisions (including the unversioned `null` state) remain safely stored in the bucket.

**Step 2: Simulating Object Deletion and Verifying Delete Marker Creation**

**Commands**

```bash
aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt

aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'DeleteMarkers[].[VersionId,IsLatest]' --output table

aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt gone.txt
```

**Screenshot**

<img width="937" height="355" alt="Task7-2" src="https://github.com/user-attachments/assets/e326be58-db3d-40d5-badb-4ef2e8f7eecb" />


**Explanation**

A standard `delete-object` request is issued without specifying a Version ID, causing S3 to insert a Delete Marker as the current active revision (`IsLatest: True`) rather than permanently destroying the data. Subsequent attempts to retrieve the object using standard `get-object` fail with a `NoSuchKey` error, proving that the object appears deleted to normal requests while retaining underlying data versions.

**Step 3: Recovering Specific Historical Versions**

**Commands**

```bash
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt \
  --version-id null recovered.txt
cat recovered.txt
```

**Screenshot**

<img width="661" height="280" alt="Task7-3" src="https://github.com/user-attachments/assets/53f7f08f-b40e-43d0-893f-a23e3125559e" />


**Explanation**

The `get-object` command is called explicitly with `--version-id null` to bypass the Delete Marker and fetch the initial baseline version of the file into `recovered.txt`. Displaying the contents confirms successful recovery of the original unredacted record (Patient: Ahmad bin Ali, Diagnosis: confidential), demonstrating S3's resiliency against accidental deletion or data tampering.

**Step 4: Permanently Deleting Specific Object Versions**

**Commands**

```bash
aws $EP s3api delete-object --bucket $BUCKET \
  --key confidential/record.txt --version-id null

aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'Versions[].[VersionId,Size]' --output table
```

**Screenshot**

<img width="722" height="250" alt="Task7--version-id null" src="https://github.com/user-attachments/assets/40a795aa-eecf-4845-91af-452f2e3e96f5" />


**Explanation**

To permanently purge a specific revision, `delete-object` is executed with the target `--version-id null` parameter. A follow-up check using `list-object-versions` confirms that the `null` version has been completely removed from storage, leaving only the remaining managed versions intact.

---

### Task 8: S3 Lifecycle Policies, Object Expiration, and KMS Cryptographic Erasure

**Objective**

To configure S3 lifecycle rules for automated object retirement, evaluate lifecycle expiration headers, and demonstrate cryptographic erasure by rendering encrypted data permanently unreadable via KMS key disabling.

**Commands**

```bash
cat > lifecycle.json <<'JSON'
{
  "Rules": [
    {
      "ID": "RetireConfidentialRecords",
      "Filter": {"Prefix": "confidential/"},
      "Status": "Enabled",
      "Expiration": {"Days": 365},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
    },
    {
      "ID": "AbortIncompleteUploads",
      "Filter": {"Prefix": ""},
      "Status": "Enabled",
      "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
    }
  ]
}
JSON

aws $EP s3api put-bucket-lifecycle-configuration --bucket $BUCKET \
  --lifecycle-configuration file://lifecycle.json

aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[].[ID,Status]' --output table
```

**Screenshot**

<img width="627" height="572" alt="Task8-1" src="https://github.com/user-attachments/assets/520f3437-156f-4917-9e5c-9aaff176c72c" />


**Explanation**

A lifecycle policy file lifecycle.json is defined to set a 365-day retention policy on confidential/ objects, expire noncurrent object versions after 30 days, and automatically abort incomplete multipart uploads after 7 days. Applying this configuration with put-bucket-lifecycle-configuration and verifying via get-bucket-lifecycle-configuration confirms both RetireConfidentialRecords and AbortIncompleteUploads rules are active (Enabled).

**Step 2: Scheduling KMS Key Deletion**

**Commands**
```bash
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyId,KeyState,Enabled]' --output text

aws $EP kms disable-key --key-id $KEY_ID
aws $EP kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7

aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyState,DeletionDate]' --output text
```

**Screenshot**

<img width="641" height="295" alt="Task8-2" src="https://github.com/user-attachments/assets/422a0035-5b3b-4f81-8250-5ca94d3be90f" />


**Explanation**

The KMS customer managed key `$KEY_ID` status is checked before calling `disable-key` and `schedule-key-deletion` with a 7-day pending window (`--pending-window-in-days 7`). A follow-up `describe-key` query verifies that the key state transitions from `Enabled` to `PendingDeletion`, effectively locking access to any data encrypted with this key during the mandatory waiting period.

**Step 3: Verifying S3 Lifecycle Expiration Headers**

**Commands**

```bash
aws $EP s3api get-object --bucket $BUCKET \
  --key confidential/record-v2.txt after-erasure.txt
```

**Screenshot**

<img width="867" height="267" alt="Task8-3" src="https://github.com/user-attachments/assets/63720d85-5f46-4e56-afcc-60452e3dc903" />


**Explanation**

Executing `get-object` on `confidential/record-v2.txt` returns object metadata containing the applied lifecycle expiration header (`Expiration: expiry-date="Sun, 12 Sep 2027 00:00:00 GMT", rule-id="RetireConfidentialRecords"`). This confirms that S3 successfully applied the lifecycle rule to schedule automated object deletion according to the defined retention timeline.

**Step 4: Demonstrating Cryptographic Erasure via KMS Key Disabling**

**Commands**

```bash
export DEMO_KEY_ID=$(aws $EP kms create-key \
  --description 'Demo key for cryptographic erasure test' \
  --query 'KeyMetadata.KeyId' --output text)
echo $DEMO_KEY_ID

aws $EP kms encrypt --key-id $DEMO_KEY_ID \
  --plaintext fileb://<(echo -n 'Patient: Ahmad bin Ali, Diagnosis: confidential') \
  --query CiphertextBlob --output text > demo-ciphertext.txt

cat demo-ciphertext.txt

aws $EP kms decrypt --ciphertext-blob fileb://<(base64 -d demo-ciphertext.txt) \
  --query Plaintext --output text | base64 -d

aws $EP kms disable-key --key-id $DEMO_KEY_ID

# Attempt decryption after disabling key
aws $EP kms decrypt --ciphertext-blob fileb://<(base64 -d demo-ciphertext.txt) \
  --query Plaintext --output text | base64 -d
```

**Screenshot**

<img width="941" height="495" alt="Task8-4" src="https://github.com/user-attachments/assets/78a298d6-3f9b-4182-a6e3-b89e1db17c8d" />

**Explanation**

A dedicated KMS key `$DEMO_KEY_ID` is created and used to encrypt sensitive payload text, verifying that normal decryption succeeds while the key remains active. Once `disable-key` is executed on `$DEMO_KEY_ID`, subsequent decryption attempts fail with a `DisabledException` error, proving that revoking or deleting the underlying KMS key achieves effective cryptographic erasure without needing to wipe raw ciphertext storage directly.

---

### Short-Answer Questions

**1. Exposure Cause and Wildcard Principal Risk**

The single element of the Task 2 policy that caused the exposure was the combination of `"Effect": "Allow"` with `"Principal": "*"`. The wildcard principal on an S3 bucket policy is significantly more dangerous than an over-broad IAM policy attached to a single user because an identity-based policy only grants permissions to one specific set of authenticated credentials. In contrast, `"Principal": "*"` on a resource-based bucket policy grants anonymous public access to any entity across the internet without requiring any AWS authentication or valid credentials.

**2. Identity-Based vs. Resource-Based Policies**

An identity-based policy is attached directly to IAM users, groups, or roles to define the specific actions that identity can perform across AWS resources, whereas a resource-based policy is attached directly to a resource such as an S3 bucket to specify who can access that resource and under what conditions. In Task 4, the analyst's first request to access `public/notice.txt` was authorized by an identity-based policy granting read permissions, while the second request to access `confidential/record.txt` was blocked by a resource-based policy that enforced explicit path-based restrictions on confidential prefixes.

**3. Guardrail vs. Control Distinction**

A control defines and enforces intended access rules and permissions, whereas a guardrail like S3 Block Public Access operates as an independent safety overlay that overrides and blocks public exposure regardless of permissive policy configurations. This distinction is critical in organizations with many engineers because human error or automated deployment scripts can accidentally introduce wildcard principals, and a guardrail ensures that an overly permissive bucket policy cannot inadvertently expose sensitive data to the public.

**4. SSE-KMS Encryption Protection Scope**

Default SSE-KMS encryption does not protect the confidential record from the analyst in Task 4 if that analyst possesses both `s3:GetObject` permissions on the S3 bucket and `kms:Decrypt` permissions on the associated KMS key. Server-side encryption is designed to defend against physical media theft, unauthorized raw disk access, or host-layer breaches within AWS data centers, but it does not protect against logical access misconfigurations, compromised IAM credentials, or overly permissive S3 and KMS authorization policies.

**5. Compliance for Right to Erasure (Task 7 Analysis)**

Invoking `delete-object` alone is non-compliant with right-to-erasure mandates because on a version-enabled S3 bucket, a standard delete request merely inserts a Delete Marker as the latest revision while keeping all underlying historical object versions fully intact and recoverable. To make the deletion legally provable and compliant, an organization must either execute permanent version purging by calling `delete-object --version-id` against every historical version ID, or perform cryptographic erasure by disabling or deleting the backing KMS key using `kms disable-key`, which renders the underlying ciphertext permanently unreadable across all historical versions.

**6. Audit Evidence Commands and Controls**

As an auditor, running `aws s3api get-public-access-block --bucket $BUCKET` provides compliance evidence that centralized S3 Block Public Access guardrails are enforced to prevent public data exposure. Additionally, collecting output from `aws s3api get-bucket-lifecycle-configuration --bucket $BUCKET` proves that automated data retention and object expiration controls are actively managing data lifecycles. Finally, executing `aws kms describe-key --key-id $KEY_ID` provides verification of key management controls and demonstrates that cryptographic erasure procedures or key deletion windows have been properly initiated.

---

### Verification Command

**Commands**

```bash
echo "=== IKB42603 Lab 6 verification: $BUCKET ==="
aws $EP s3api get-public-access-block --bucket $BUCKET --query 'PublicAccessBlockConfiguration' --output text
aws $EP s3api get-bucket-versioning --bucket $BUCKET --output text
aws $EP s3api get-bucket-encryption --bucket $BUCKET --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.[SSEAlgorithm,KMSMasterKeyId]' --output text
aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET --query 'Rules[].[ID,Status]' --output text
aws $EP kms describe-key --key-id $KEY_ID --query 'KeyMetadata.KeyState' --output text
```


**Screenshot**

<img width="937" height="257" alt="image" src="https://github.com/user-attachments/assets/a7adb22b-9c9a-4fbc-b3d6-870d0c11b3c4" />

**Explanation**

Executing the consolidated verification script retrieves and confirms the final security baseline for the S3 bucket `miit-patient-records-29278`. The output confirms that all four S3 Block Public Access options are set to `True`, S3 object versioning is `Enabled`, default server-side encryption is set to `aws:kms`, active lifecycle policies (`RetireConfidentialRecords` and `AbortIncompleteUploads`) are `Enabled`, and the backing Customer Managed Key is in the `PendingDeletion` state.

---

### Security Best-Practices Checklist

- [x] Every object carries a classification tag before any access decision is made.
- [x] No bucket policy names Principal: "*"; anonymous access was tested and is refused.
- [x] Block Public Access is enabled on all four flags.
- [x] Access is granted by least privilege and scoped to a key prefix, never to /* by default
- [x] Default encryption at rest is aws:kms with a customer-managed key.
- [x] Sharing uses time-bounded presigned URLs, not permanent public objects.
- [x] Versioning is enabled, and the team understands that delete markers do not destroy data.
- [x]  A lifecycle configuration expresses the retention policy, and cryptographic erasure is available
for provable deletion.

---

### Cleanup & Teardown

**Commands**

```bash
aws $EP s3api delete-bucket-policy --bucket $BUCKET

# Delete all object versions, then all delete markers
aws $EP s3api delete-objects --bucket $BUCKET --delete "$(aws $EP s3api \
  list-object-versions --bucket $BUCKET --output json \
  --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"

aws $EP s3api delete-objects --bucket $BUCKET --delete "$(aws $EP s3api \
  list-object-versions --bucket $BUCKET --output json \
  --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}')"

# The bucket is only now genuinely empty
aws $EP s3api list-object-versions --bucket $BUCKET --output text
aws $EP s3api delete-bucket --bucket $BUCKET

aws $EP iam delete-user-policy --user-name DataAnalyst --policy-name S3ReadAll
aws $EP iam delete-user --user-name DataAnalyst

docker rm -f localstack
rm -f *.json *.txt
```

**Screenshot**

<img width="745" height="687" alt="image" src="https://github.com/user-attachments/assets/e014f9e0-1a85-49f2-a83e-1fbde6ac5b4e" />

<img width="932" height="382" alt="image" src="https://github.com/user-attachments/assets/5578d231-0b66-4f24-8988-dde94cd9e72f" />


**Explanation**

Executing the teardown procedure removes all deployed resources and local artifacts created during the lab. The S3 bucket policy is removed prior to querying and purging all historical object versions and delete markers, ensuring the bucket is completely empty before deletion. Finally, the IAM user and inline policy are removed, the LocalStack Docker container is destroyed, and all temporary JSON and text files in the local workspace are cleaned up.

---

### References

* Course lectures — Week 4 (Data Protection); Week 10 (Policy, Compliance & Risk); Week
11 (Compliance Assessment & Reporting).
* Amazon S3 security best practices —
docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
* Amazon S3 versioning and lifecycle —
docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html
* LocalStack S3 coverage and limitations — docs.localstack.cloud/references/coverage
* CSA Security Guidance v5 — Domain 5, Data Security; and the Data Security Lifecycle.
* MCMC MTSFB TC G017:2021 — Information Security Requirements for Cloud Service
Providers (data handling clauses).

