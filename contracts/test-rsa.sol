// SPDX-License-Identifier: MIT

pragma solidity ^0.8.30;

import "./rsa.sol";


/*
 *  A quick demo of my RSA library for recovering hashes from standard
 *  RSA signed data.
 *
 *  See: https://blog.ricmoo.com/ethereum-and-rsa-ae86218300a3
 */

contract TestRSA {

    function recoverHashRSA1024(bytes32[4] memory modulus, uint exponent,
      bytes32[4] memory signature) external view
      returns (bool success, bytes32 hash) {
        return RSA1024.recoverHash(modulus, exponent, signature);
    }

    function recoverHashRSA2048(bytes32[8] memory modulus, uint exponent,
      bytes32[8] memory signature) external view
      returns (bool success, bytes32 hash) {
        return RSA2048.recoverHash(modulus, exponent, signature);
    }

    function recoverHashRSA3072(bytes32[12] memory modulus, uint exponent,
      bytes32[12] memory signature) external view
      returns (bool success, bytes32 hash) {
        return RSA3072.recoverHash(modulus, exponent, signature);
    }

    function recoverHashRSA4096(bytes32[16] memory modulus, uint exponent,
      bytes32[16] memory signature) external view
      returns (bool success, bytes32 hash) {
        return RSA4096.recoverHash(modulus, exponent, signature);
    }
}
