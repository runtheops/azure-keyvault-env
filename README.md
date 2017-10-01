# Azure KeyVault Env
[![Build Status](https://travis-ci.org/runtheops/azure-keyvault-env.svg?branch=master)](https://travis-ci.org/runtheops/azure-keyvault-env)

A tool that populates secrets stored in Azure Keyvault into environment variables. It can also write them out to files. An idea behind it is to have a simple way to securely store secrets and populate them in Docker containers on instances running in Azure.

It is inspired by [remind101/ssm-env](https://github.com/remind101/ssm-env) project and is heavily based on [cosmincojocar/adal-go cmd](https://github.com/cosmincojocar/adal/blob/master/cmd/adal.go).


Special thanks to [@yanzay](https://github.com/yanzay) for his help and contribution.

# Running
Secrets from Key Vault will be exported as env variables:
```
azure-keyvault-env -vaultName <vault name> \
    -tenantId <tenant ID> \
    -applicationId <application ID> \
    -certificatePath path/to/certificate \
    -servicePrefix <service prefix>
```
Will result an output as follows:
```
export SECRET="SecretValue"
```
* Secret name from Azure Key Vault will be in upper-case
* `-` will be replaced with `_`
* Serice prefix will be cut
* `-file` suffix will be cut
> secret name in Key Vault limited to regex pattern: `^[0-9a-zA-Z-]+$`

Configuration can also be made via env variables, prefixed with `AKE_`:
```
AKE_VAULTNAME=<vault name>
AKE_TENANTID=<tenant ID> 
AKE_APPLICATIONID=<application ID>
AKE_CERTIFICATEPATH=path/to/certificate
AKE_SERVICEPREFIX=<service prefix>
```

`servicePrefix` is used to filter keys in Key Vaults for particular service (i.e. docker container)

Aforementioned ends up with:
```
eval $(azure-keyvault-env)
```
which populates env variables from Key Vault and overrides current env.

# Writing secrets to files

**SecretValue in this case is expected to be base64 encoded and first line of file should be location of destination file**
Otherwise util will fail on a decode step.

Given secret `service-secret-file` in key vault with value
```
L3BhdGgvdG8vc2VjcmV0DQpTZWNyZXRWYWx1ZQ0KbXVsdGkgbGluZQ0K
```
Output will be:
```
export SECRET=/path/to/secret
```
and SecretValue except the first line will be written to a `/path/to/secret` file
