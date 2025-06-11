// SPDX-License-Identifier: MIT

pragma solidity ^0.8.30;


/*
 *  A simple RSA library.
 */


library _RSALib {

    // Append a 256-bit number
    function appendUint(bytes memory output, uint offset, uint value)
      pure internal returns (uint) {
        assembly {
            mstore(add(add(output, 32), offset), value)
        }
        return 32;
    }

    // Append a number, length bytes long from the lsb.
    function appendNumber(bytes memory output, uint offset, uint value,
      uint length) pure internal returns (uint) {

        uint shift = length * 8;
        while (shift != 0) {
            shift -= 8;
            output[offset++] = bytes1(uint8((value >> shift) & 0xff));
        }
        return length;
    }

    // Setup the expmod parameters
    function dataInitExpmod(uint byteCount, uint exp) pure internal
      returns (uint offset, uint expLength, bytes memory output) {

        offset = 0;

        expLength = 0;
        while (exp != 0) {
            expLength++;
            exp >>= 8;
        }

        // Allocate space to call to expmod
        // - [ base.length=128 (32 bytes) ]
        // - [ exponent.length=expLength (32 bytes) ]
        // - [ modulus.length=128 (32 bytes) ]
        // - [ base.value=sig (byteCount bytes) ]
        // - [ exponent.value=exp (expLength bytes) ]
        // - [ modulus.value=modulus (byteCount bytes) ]
        output = new bytes((3 * 32) + byteCount + expLength + byteCount);

        // base.length
        offset += _RSALib.appendUint(output, offset, byteCount);

        // exponent.length
        offset += _RSALib.appendUint(output, offset, expLength);

        // modulus.length
        offset += _RSALib.appendUint(output, offset, byteCount);
    }

    // Compute the expmod
    function expmod(bytes memory params, uint byteCount, bytes32 prefix)
      view internal returns (bool success, bytes32 hash) {

        uint length;
        bytes32 prefixHash;
        assembly {

            // Call expmod(sig, exp, modulus); store the result back on param
            success := staticcall(gas(), 5, add(params, 32), mload(params),
              add(params, 32), mload(params))
            length := returndatasize()

            // The hash of the prefix of the result (sans the hash)
            prefixHash := keccak256(add(params, 32), sub(byteCount, 32))

            // The (n-1)th word of the result; we check the prefix below
            // (the params length puts us 1 word behind, where we want to be)
            hash := mload(add(params, byteCount))
        }

        // The prefix didn't match or the expmod returned a bad length
        if (prefixHash != prefix || length != byteCount) {
            success = false;
        }
    }
}

library RSA1024 {

    uint internal constant bitCount = 1024;
    uint internal constant byteCount = 128;
    uint internal constant wordCount = 4;

    // The hash of the first 96 bytes of a PKCS#1 v1.5 RSA-1024 payload
    // [ 0x00, 0x01, PADDING * 0xff, 0x00, ASN.1/DER prefix for sha-256 ]
    // i.e.
    //   0x0001
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffff
    //   00
    //   3031300d060960864801650304020105000420
    bytes32 internal constant PKCS1_PREFIX_HASH =
      0x4597ce432cfefc794321e09e4913ece6385e2d942a52e8742c09adc32d24a8d7;

    /**
     *  Recover the digest that was signed by a 1024-bit RSA private key
     *  whose public key (modulus, exponent) created the signature.
     *
     *  This assumes the digest was hashed with SHA2-256 and was encoded
     *  as PKCS#1 v1.5.
     */
    function recoverHash(bytes32[4] memory modulus, uint exponent,
      bytes32[4] memory signature) internal view
      returns (bool success, bytes32 hash) {

        (uint offset, uint expLength, bytes memory params) =
          _RSALib.dataInitExpmod(byteCount, exponent);

        // base.value=signature
        assembly { mcopy(add(add(params, 32), offset), signature, byteCount) }
        offset += byteCount;

        // exponent.value=exponent
        offset += _RSALib.appendNumber(params, offset, exponent, expLength);

        // modulus.value=modulus
        assembly { mcopy(add(add(params, 32), offset), modulus, byteCount) }

        (success, hash) = _RSALib.expmod(params, byteCount,
          PKCS1_PREFIX_HASH);

        //hash = modulus[0];
    }

}

library RSA2048 {

    uint internal constant bitCount = 2048;
    uint internal constant byteCount = 256;
    uint internal constant wordCount = 8;

    // The hash of the first 224 bytes of a PKCS#1 v1.5 RSA-2048 payload
    // [ 0x00, 0x01, PADDING * 0xff, 0x00, ASN.1/DER prefix for sha-256 ]
    // i.e.
    //   0x0001
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffff
    //   00
    //   3031300d060960864801650304020105000420
    bytes32 internal constant PKCS1_PREFIX_HASH =
      0xce73212fcc669c1c39c7025ef6bf6ae940e12ff54a237d8f5fbacc2f1468d39c;


    /**
     *  Recover the digest that was signed by a 2048-bit RSA private key
     *  whose public key (modulus, exponent) created the signature.
     *
     *  This assumes the digest was hashed with SHA2-256 and was encoded
     *  as PKCS#1 v1.5.
     */
    function recoverHash(bytes32[8] memory modulus, uint exponent,
      bytes32[8] memory signature) internal view
      returns (bool success, bytes32 hash) {

        (uint offset, uint expLength, bytes memory params) =
          _RSALib.dataInitExpmod(modulus.length * 32, exponent);

        // base.value=signature
        assembly { mcopy(add(add(params, 32), offset), signature, byteCount) }
        offset += byteCount;

        // exponent.value=exponent
        offset += _RSALib.appendNumber(params, offset, exponent, expLength);

        // modulus.value=modulus
        assembly { mcopy(add(add(params, 32), offset), modulus, byteCount) }

        (success, hash) = _RSALib.expmod(params, modulus.length * 32,
          PKCS1_PREFIX_HASH);
    }
}

library RSA3072 {

    uint internal constant bitCount = 3072;
    uint internal constant byteCount = 384;
    uint internal constant wordCount = 12;

    // The hash of the first 352 bytes of a PKCS#1 v1.5 RSA-3072 payload
    // [ 0x00, 0x01, PADDING * 0xff, 0x00, ASN.1/DER prefix for sha-256 ]
    // i.e.
    //   0x0001
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffff
    //   00
    //   3031300d060960864801650304020105000420
    bytes32 internal constant PKCS1_PREFIX_HASH =
      0x472777a6bf4bec70a5b6ab47130dee04e61b87a46532a5bcdb7707c5764c7bc1;


    /**
     *  Recover the digest that was signed by a 3072-bit RSA private key
     *  whose public key (modulus, exponent) created the signature.
     *
     *  This assumes the digest was hashed with SHA2-256 and was encoded
     *  as PKCS#1 v1.5.
     */
    function recoverHash(bytes32[12] memory modulus, uint exponent,
      bytes32[12] memory signature) internal view
      returns (bool success, bytes32 hash) {

        (uint offset, uint expLength, bytes memory params) =
          _RSALib.dataInitExpmod(modulus.length * 32, exponent);

        // base.value=signature
        assembly { mcopy(add(add(params, 32), offset), signature, byteCount) }
        offset += byteCount;

        // exponent.value=exponent
        offset += _RSALib.appendNumber(params, offset, exponent, expLength);

        // modulus.value=modulus
        assembly { mcopy(add(add(params, 32), offset), modulus, byteCount) }

        (success, hash) = _RSALib.expmod(params, modulus.length * 32,
          PKCS1_PREFIX_HASH);
    }
}

library RSA4096 {

    uint internal constant bitCount = 4096;
    uint internal constant byteCount = 512;
    uint internal constant wordCount = 16;

    // The hash of the first 480 bytes of a PKCS#1 v1.5 RSA-4096 payload
    // [ 0x00, 0x01, PADDING * 0xff, 0x00, ASN.1/DER prefix for sha-256 ]
    // i.e.
    //   0x0001
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //   ffffffffffffffffffff
    //   00
    //   3031300d060960864801650304020105000420
    bytes32 internal constant PKCS1_PREFIX_HASH =
      0x01277f6c3e6e171739f2cd4e81379447cb8a8a7f6164895387d005f7c02ef34d;

    /**
     *  Recover the digest that was signed by a 4096-bit RSA private key
     *  whose public key (modulus, exponent) created the signature.
     *
     *  This assumes the digest was hashed with SHA2-256 and was encoded
     *  as PKCS#1 v1.5.
     */
    function recoverHash(bytes32[16] memory modulus, uint exponent,
      bytes32[16] memory signature) internal view
      returns (bool success, bytes32 hash) {

        (uint offset, uint expLength, bytes memory params) =
          _RSALib.dataInitExpmod(modulus.length * 32, exponent);

        // base.value=signature
        assembly { mcopy(add(add(params, 32), offset), signature, byteCount) }
        offset += byteCount;

        // exponent.value=exponent
        offset += _RSALib.appendNumber(params, offset, exponent, expLength);

        // modulus.value=modulus
        assembly { mcopy(add(add(params, 32), offset), modulus, byteCount) }

        (success, hash) = _RSALib.expmod(params, modulus.length * 32,
          PKCS1_PREFIX_HASH);
    }
}
