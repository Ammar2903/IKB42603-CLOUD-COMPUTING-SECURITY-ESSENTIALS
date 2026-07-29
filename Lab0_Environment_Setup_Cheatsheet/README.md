# Lab 0: Environment Setup Report

**Course:** IKB42603 Cloud Computing Security Essentials  
**Lab:** Lab 0 - Environment Setup  
**Guide used:** `IKB42603_Lab0_Environment_Setup_Cheatsheet.pdf`  
**Evidence folder:** `Evidence/`

## 1. Objective

The objective of this lab was to install, configure, and verify the local tools required before starting Lab 1. The setup follows the Lab 0 Environment Setup Cheatsheet and prepares a local cloud security lab environment using Docker, AWS CLI, LocalStack, kind, kubectl, OpenSSL, and oathtool.

The lab environment is designed to run locally without using a real AWS account. AWS CLI commands are pointed to LocalStack using the endpoint `http://localhost:4566`.

## 2. Tools Required by the Guide

| Tool | Purpose | Used In |
| --- | --- | --- |
| Docker | Runs containers and the LocalStack cloud simulator | All labs |
| AWS CLI v2 | Sends AWS commands to LocalStack | Labs 1, 3, 5 |
| kind | Runs a local Kubernetes cluster inside Docker | Labs 1, 2, 4 |
| kubectl | Controls the Kubernetes cluster | Labs 1, 2, 4 |
| OpenSSL | Supports encryption, keys, and certificates | Lab 3 |
| oathtool | Generates MFA/TOTP codes | Lab 4 |
| Trivy | Scans container images for vulnerabilities through Docker | Lab 4 |

## 3. Docker Installation and Verification

Docker serves as the foundational container engine required to host both the LocalStack environment and the Kubernetes node instances provisioned by kind.

### Steps

1. Install Docker according to the operating system.
2. Start Docker.
3. Verify the Docker installation:

```bash
docker --version
```

### Result

The system returned the installed Docker engine build details, confirming the service is active and ready for container execution:

```text
Docker version 28.5.2+dfsg4, build 9cc6dea35e9a963f281434761c656fba4ac43aed
```

### Evidence

<img width="631" height="62" alt="Image" src="https://github.com/user-attachments/assets/dc12f942-f241-4741-9579-f0edc7ad44b0" />

## 4. AWS CLI v2 Installation and Verification

The AWS Command Line Interface (AWS CLI v2) allows execution of AWS-formatted commands directly against the local LocalStack instance without interacting with live AWS cloud infrastructure.

### Steps

1. Install AWS CLI v2.
2. Verify the AWS CLI installation:

```bash
aws --version
```

### Result

AWS CLI v2 was successfully installed. The command returned:

```text
aws-cli/2.36.8 Python/3.14.6 Linux/6.18.12+kali-amd64 exe/x86_64.kali.2026
```

### Evidence

<img width="625" height="70" alt="Image" src="https://github.com/user-attachments/assets/461c21fa-fe10-4846-902f-e68f358fb22a" />

## 5. kind and kubectl Installation and Verification

The guide requires kind for creating a Kubernetes cluster inside Docker and kubectl for controlling that cluster.

### Steps

1. Install kind.
2. Install kubectl.
3. Verify kind:

```bash
kind --version
```

4. Verify kubectl:

```bash
kubectl version --client
```

### Result

kind was successfully installed and verified:

```text
kind version 0.23.0
```

kubectl was also installed and verified:

```text
Client Version: v1.33.4
Kustomize Version: v5.5.0
```

One screenshot shows an earlier `kind` execution format error, which indicates the wrong binary architecture was attempted at first. This was resolved, as confirmed by the later successful kind verification screenshot.

### Evidence

<img width="242" height="52" alt="Image" src="https://github.com/user-attachments/assets/23bbec07-83f6-47d1-8336-f88aa8415b0f" />

<img width="312" height="70" alt="Image" src="https://github.com/user-attachments/assets/4b8efc6e-69b2-4a2c-aac5-c05cb5088ca9" />

## 6. Helper Tools Verification

The guide lists OpenSSL and oathtool as helper tools. OpenSSL is used for encryption, keys, and certificates. oathtool is used for MFA/TOTP code generation.

### Steps

1. Verify OpenSSL:

```bash
openssl version
```

2. Verify oathtool:

```bash
oathtool --version
```

### Result

OpenSSL was verified successfully:

```text
OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)
```

oathtool was verified successfully:

```text
oathtool (OATH Toolkit) 2.6.14
```

### Evidence

<img width="541" height="65" alt="Image" src="https://github.com/user-attachments/assets/8c246db5-f77f-417a-822b-eca31a4dec49" />

<img width="677" height="155" alt="Image" src="https://github.com/user-attachments/assets/4157a019-0721-4e62-8a28-7c1927d73079" />

## 7. LocalStack Startup and Verification

LocalStack provides the local AWS-compatible environment used by the labs.

### Steps

1. Start LocalStack:

```bash
docker run -d --name localstack -p 4566:4566 localstack/localstack
```

2. Check that the container is running:

```bash
docker ps
```

3. Confirm LocalStack health:

```bash
curl http://localhost:4566/_localstack/health
```

### Result

The Docker process list shows the LocalStack container running with healthy status:

```text
CONTAINER ID   IMAGE                        COMMAND                  CREATED       STATUS                  PORTS                                                                                 NAMES
9fcbff6256d0   localstack/localstack:4.4.0   "docker-entrypoint.sh"   6 hours ago   Up 6 hours (healthy)   4510-4559/tcp, 5678/tcp, 0.0.0.0:4566->4566/tcp, [::]:4566->4566/tcp   localstack
```

### Evidence

<img width="852" height="112" alt="Image" src="https://github.com/user-attachments/assets/c0645b0c-745c-4d45-a06b-b3e6976baa0b" />

## 8. Kubernetes Cluster Creation and Verification

The guide requires creating a local Kubernetes cluster with kind and verifying it using kubectl.

### Steps

1. Create the cluster:

```bash
kind create cluster --name ccse
```

2. Verify cluster information:

```bash
kubectl cluster-info --context kind-ccse
```

3. Verify cluster nodes:

```bash
kubectl get nodes
```

### Result

The Kubernetes cluster was created successfully. The cluster information shows that the Kubernetes control plane and CoreDNS are running.

The node list shows the cluster control plane is ready:

```text
NAME                 STATUS   ROLES           AGE   VERSION
ccse-control-plane   Ready    control-plane   36s   v1.30.0
```

The Docker process list also shows the kind node container running:

```text
kindest/node:v1.30.1
Name: ccse-control-plane
```

### Evidence

<img width="772" height="252" alt="Image" src="https://github.com/user-attachments/assets/2f910c46-ed19-4525-b285-09e1518159ec" />

<img width="472" height="121" alt="Image" src="https://github.com/user-attachments/assets/15786e2f-66ce-40c6-b72e-0bf768cd1dc3" />

## 9. One-Time AWS CLI Configuration for LocalStack

The guide explains that LocalStack accepts dummy AWS credentials. These values are configured so the AWS CLI does not prompt for credentials.

### Steps

1. Configure a dummy AWS access key:

```bash
aws configure set aws_access_key_id test
```

2. Configure a dummy AWS secret access key:

```bash
aws configure set aws_secret_access_key test
```

3. Configure the default AWS region:

```bash
aws configure set region us-east-1
```

4. Set the LocalStack endpoint variable for the current shell session:

```bash
EP='--endpoint-url=http://localhost:4566'
```

5. Test AWS CLI communication with LocalStack:

```bash
aws $EP sts get-caller-identity
```

### Result

The AWS CLI successfully communicated with LocalStack and returned a dummy identity:

```json
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}

```

### Evidence

<img width="472" height="121" alt="Image" src="https://github.com/user-attachments/assets/204c450e-c74f-40a2-a3d4-71eefb983e86" />

## 10. Pre-Lab Verification Checklist

| Check | Status | Evidence |
| --- | --- | --- |
| `docker --version` prints a version | Complete | `Evidence/1.docker.png` |
| `aws --version` prints AWS CLI v2 | Complete | `Evidence/2.awscli.png` |
| `kind --version` works | Complete | `Evidence/3.1-kind.png` |
| `kubectl version --client` works | Complete | `Evidence/3.kubectl.png` |
| OpenSSL works | Complete | `Evidence/4.Helper.png` |
| oathtool works | Complete | `Evidence/4.Helper.png` |
| LocalStack container starts | Complete | `Evidence/5.localstack.png` |
| LocalStack is healthy | Complete | `Evidence/5.localstack.png` |
| Kubernetes cluster is created | Complete | `Evidence/5.1.kubenetes.png` |
| `kubectl get nodes` shows a ready node | Complete | `Evidence/5.1.kubenetes.png` |
| AWS CLI can call LocalStack STS | Complete | `Evidence/6-config.png` |

## 11. Troubleshooting Notes

During verification, an earlier screenshot showed:

```text
zsh: exec format error: kind
```

This usually happens when the installed binary does not match the system architecture. The issue was resolved by using a working kind binary, as shown by:

```text
kind version 0.23.0
```

This confirms that the final kind installation is working.

## 12. Conclusion

The Lab 0 environment setup was completed successfully. Docker, AWS CLI v2, kind, kubectl, OpenSSL, oathtool, LocalStack, and the local Kubernetes cluster were installed or verified according to the setup guide. AWS CLI was configured with dummy credentials and successfully connected to LocalStack through the local endpoint.

The system is ready for Lab 1.
