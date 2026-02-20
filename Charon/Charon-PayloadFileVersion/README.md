# Charon - Payload File Version

## 🛠 Key Improvements & Changes

### 1. External UUID Staging (Static Bypass)
Unlike the original version which embedded the payload as a static resource (often flagged due to high entropy or suspicious code-to-data ratios), this version introduces **Decoupled Staging**.
* **Mechanism**: The payload is now stored in an external `.enc` file.
* **Obfuscation**: The staged file is encoded as a series of UUID strings. This transforms high-entropy encrypted data into a low-entropy ASCII format, bypassing static "Encrypted/Packed Payload" detections.

## 🕯️ Updated Ritual (New Usage)

The build process now requires an additional step to prepare the external payload.

### Step 1: Encrypt the Payload
Use the new Python utility to generate your obfuscated staging file:
```bash
python UUIDEncrypter.py havoc.bin payload.enc
```

### Step 2: Build the Artifact
Compile the updated Charon builder and generate the vessel:
```bash
cl Charon.c
.\Charon.exe
```

### Step 3: Execution
On the target machine, the artifact now requires the path to the external soul (payload) as a command-line argument:
```bash
.\CharonArtifact.exe payload.enc
```
