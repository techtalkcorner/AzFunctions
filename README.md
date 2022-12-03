# Azure Functions PgpCore
Azure Functions C# sample for PGP encrypt and decrypt.
This is based on code from [ikaur3009](https://github.com/ikaur3009) and [PgpCore](https://github.com/mattosaurus/PgpCore) library.
## Azure Key Vault
Added Azure Key Vault integration 2022-04-26
## Usage
### Keypair issues
*BouncyCastle unknown packet type encountered: 20* when decrypting using exported private key from GnuPG/Gpg4win. Generate Keypair using this library, import public key to GPG/Gpg4win keyring of source server, and configure private key in Function app.
### Environment Variables
```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage":"DefaultEndpointsProtocol=https;AccountName=myAccountName;AccountKey=myAccountKey",
    "AzureStagingStorage":"DefaultEndpointsProtocol=https;AccountName=myAccountName;AccountKey=myAccountKey",
    "KEY_VAULT_NAME":"kvURI",
  }
}
```
### Invoke
GenKeys
```json
POST http://localhost:7071/api/PGPGenKeys?
{
  "outputPath":"container/folder/publickey.asc",
  "email":"email@address.com",
  "passPhrase":"privateKeypassphrase"
  "kvsecpass":"passPhraseKeyVaultSecret",
  "kvsecpriv":"privateKeyKeyVaultSecret"
}
```
Decrypt
```json
POST http://localhost:7071/api/PGPDecrypt?
{
  "filePath":"container/folder/inputfilename",
  "outputPath":"container/folder/outputfilename",
  "kvsecpass":"passPhraseKeyVaultSecret",
  "kvsecpriv":"privateKeyKeyVaultSecret"
}  
```
Encrypt (still using public key path from environment PGP_PublicKey)
```json
POST http://localhost:7071/api/PGPEncrypt?
{
  "filePath":"container/folder/inputfilename",
  "outputPath":"container/folder/outputfilename",
}
```
### Publish
[Publish to Azure](https://docs.microsoft.com/en-us/azure/azure-functions/functions-develop-vs?tabs=in-process#publish-to-azure)
