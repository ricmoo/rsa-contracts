Solidity RSA Library
====================

[![CI Tests](https://github.com/ricmoo/rsa-contracts/actions/workflows/test.yml/badge.svg)](https://github.com/ricmoo/rsa-contracts/actions/workflows/test.yml)

Simple RSA verification library for Solidity contracts.


Library Setup
-------------

```
# Using NPM
/home/ricmoo/my-project> npm install rsa-contracts
```

From your Solidity:

```solidity
import "rsa-contracts/contract/lib-rsa.sol";

contract MyContract {
    function validateRSA3072(bytes32 hash, bytes32[12] memory pubkey,
      bytes32[12] memory sig) public returns (bool) {
        return RSA3072.recoverHash(pubkey, 65537, sig) == hash;
    }
}
```


API
---

The API for each of the supported keypair sizes is the same, only
differing in the number of `bytes32` words that make up the modulus and
signature, which must match the keypair size.

```
// RSA 1024-bit
RSA1024.recoverHash(bytes32[4] modulus, uint exponent, bytes32[4] sig)
  returns (bytes32)

// RSA 2048-bit
RSA2048.recoverHash(bytes32[8] modulus, uint exponent, bytes32[8] sig)
  returns (bytes32)

// RSA 3072-bit
RSA3072.recoverHash(bytes32[12] modulus, uint exponent, bytes32[12] sig)
  returns (bytes32)

// RSA 4096-bit
RSA4096.recoverHash(bytes32[16] modulus, uint exponent, bytes32[16] sig)
  returns (bytes32)
```

RSA public keys have two components, the **modulus** (also called **n**)
and the **exponent** (also called **e**).

The coresponding private key can be used to efficiently compute a
**signature** such that:

`digest = (signature ** exponent) % modulus`

So, during signing the payload is hashed using SHA2-256 into a **digest**,
then encoded with PKCS#1 v1.5 to pad the 256-bit digest up to the necessary
key size (for example, 3072-bits). The private key then computes the
signature.

To verify the signed content, these contract methods can be used to recover
the original hash which can then be checked against the expected value.

`require(RSA3072.recoverHash(modulus, 65537, signature) == digest);`

The vast majority of RSA usage expect the exponent `65537`, so usually it
can be omitted from the public key and you need only provide the modulus,
hard-coding the exponent where necessary. That depends on the system you
are using though.


License
-------

MIT License
