# Azure KeyVault Env

A tool that populates secrets stored in Azure Keyvault into environment variables. It can also write them out to files. An idea behind it is to have a simple way to securely store secrets and populate them in Docker containers on instances running in Azure.

It is inspired by [remind101/ssm-env](https://github.com/remind101/ssm-env) project and is heavily based on [cosmincojocar/adal-go cmd](https://github.com/cosmincojocar/adal/blob/master/cmd/adal.go).


Special thanks to [@yanzay](https://github.com/yanzay) for his help and contribution.

# Running
Given following environment
```
SECRET=keyvault://SecretName
```
and secret stored under SecretName in a corresponding Key Vault:
```
azure-keyvault-env -vaultName <vault name> \
    -tenantId <tenant ID> \
    -applicationId <application ID> \
    -certificatePath path/to/certificate
```
Will result an output as follows:
```
export SECRET="SecretValue"
```
Configuration can also be made via env variables, prefixed with `AZURE_`:
```
AZURE_VAULTNAME=<vault name>
AZURE_TENANTID=<tenant ID> 
AZURE_APPLICATIONID=<application ID>
AZURE_CERTIFICATEPATH=path/to/certificate
```
Aforementioned ends up with:
```
eval $(azure-keyvault-env)
```
which populates env variables from Key Vault and overrides current env.

# Writing secrets to files

**SecretValue in this case is expected to be base64 encoded!**
Otherwise util will fail on a decode step.

Given the environment:
```
SECRET=keyvault://SecretName:/path/to/secret
```
Output will be:
```
export SECRET=/path/to/secret
```
and SecretValue will be written to a `/path/to/secret` file
