# CertsBuilder
A Human way to create certificates

### Prerequisites
The script is using cryptography>=2.1.3 and was built for python3

## How to use it:
Print the scripts help
```
-h, --help
```

Print the script's version
```
--version
```

Set the output directory to use. If the directory already exists the script will fail.
We fail it so we won't get to a situation that we will have a directory with mixed certificates
which are of different root CAs. 
Default is *certs/* in linux and *certs\\* in windows.
```
--certs_dir
```

Set the depth of the chain to create. The depth is the number of intermediate CA certificates.
Default is *0*.
```
--depth
```

Set the number of CA branches to create. Use it when you want your root CA to create number
of intermediate CAs that each of them will have their own chain. Note: this flag has no affect
if the --depth is set to 0.
Default is 1.
```
--split_authorities
```

Export the certificate chain for each end entity certificate.
Default is *False*.
```
--export_chain
```

Set the number of end entity certificates to create at the end of each intermediate chain.
Default is *1*.
```
--certs
```

Set the number of certificates to revoke out of the end entity certificates created per chain.
When using this flag, the script will also create CRL file, index.txt file (used with openssl ocsp)
and a file with openssl ocsp command that runs a small ocsp server locally.
Default is *0*.
```
--revoked
```

Set the number of days the certificates will be valid for. The value can be negative which will set the
notBefore to be X days before today and notAfter to current time. Use negative value when you wish to
create expired certificates.
**Default** is *3650* (10 Years).
```
--days
```

Set the private and public key type to create.
**Default** is *RSA*. 
**Supported values**: *rsa, ec*.
```
--key_type
```

Set the RSA key size.
**Default** is *2048*. 
**Supported values**: *512, 1024, 2048, 4096, 8192, 16384*.
```
--key_size
```

Set the EC key size. The size of EC key is derived from the curved used.
**Default** is *SECP256R1*. 
**Supported values**: 
  *SECT163R2, SECP224R1, SECP384R1, SECP256K1, SECT409R1, SECT571K1, SECT283R1, SECP192R1,
  SECP521R1, SECP256R1, SECT571R1, SECT233K1, SECT283K1, SECT233R1, SECT163K1, SECT409K1*.
```
--ec_curve
```

Set the hash algorithm to use when signing the certificate. 
The signature algorithm is derived from both hash and key type. 
Example: sha256WithRSAEncryption is SHA256 hash and RSA key type.
**Default** is *SHA256*.
**Supported values**: *BLAKE2b, BLAKE2s, MD5, SHA1, SHA224, SHA256, SHA384, SHA512*.
```
--hash_alg
```

## Author
**Dror Moyal**
