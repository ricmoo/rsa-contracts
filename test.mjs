import { readFileSync } from "node:fs";

import { ethers } from "ethers";

import { compile, splitBytes32 } from "./utils.mjs";


// Load the contract and tests
const { abi, bytecode } = compile("TestRSA")
const tests = JSON.parse(readFileSync("./testcases.json").toString());


(async function() {
    // Connect to a local Geth instance
    const provider = new ethers.JsonRpcProvider();
    const signer = await provider.getSigner();

    // Deploy the contract
    const factory = new ethers.ContractFactory(abi, bytecode, signer);
    const contract = await factory.deploy();
    const receipt = await contract.waitForDeployment();

    let pass = 0, fail = 0;

    // Track gas costs
    const stats = { };
    const addStat = (size, exp, gas) => {
        const key = `(RSA ${ size }-bit e=${ exp })`;
        let stat = stats[key]
        if (!stat) {
            stat = { totalGas: 0n, count: 0n };
            stats[key] = stat;
        }
        stat.totalGas += gas;
        stat.count++;
    };

    // Test for valid RSA hash recovery
    for (const test of tests) {

        // Get the testcase info and format it for the contract
        const mod = splitBytes32(test.modulus);
        const exp = test.exponent;
        const sig = splitBytes32(test.signature);

        // Run the contract call (and estimate gas)
        let result;
        switch (test.size) {
            case 1024:
                result = await contract.recoverHashRSA1024(mod, exp, sig);
                addStat(
                    test.size, exp,
                    await contract.recoverHashRSA1024.estimateGas(mod, exp, sig)
                );
                break;
            case 2048:
                result = await contract.recoverHashRSA2048(mod, exp, sig);
                addStat(
                    test.size, exp,
                    await contract.recoverHashRSA2048.estimateGas(mod, exp, sig)
                );
                break;
            case 3072:
                result = await contract.recoverHashRSA3072(mod, exp, sig);
                addStat(
                    test.size, exp,
                    await contract.recoverHashRSA3072.estimateGas(mod, exp, sig)
                );
                break;
            case 4096:
                result = await contract.recoverHashRSA4096(mod, exp, sig);
                addStat(
                    test.size, exp,
                    await contract.recoverHashRSA4096.estimateGas(mod, exp, sig)
                );
                break;
            default:
                console.log(test);
                throw new Error(`unknown key size`)
        }

        // Check the result
        if (result.success && result.hash === ("0x" + test.hash)) {
            pass++;
        } else {
            fail++;
            console.log(test.size, test.exponent, test.hash, result);
        }
    }

    // Test for correct failure on incorrect signature
    for (const test of tests) {

        // Get the testcase info and format it for the contract
        const mod = splitBytes32(test.modulus);
        const exp = test.exponent;

        // Twiddle a single bit within the signature
        const _sig = ethers.getBytes("0x" + test.signature);
        _sig[100] ^= 0x02;
        const sig = splitBytes32(ethers.hexlify(_sig).substring(2));

        // Run the contract call
        let result;
        switch (test.size) {
            case 1024:
                result = await contract.recoverHashRSA1024(mod, exp, sig);
                break;
            case 2048:
                result = await contract.recoverHashRSA2048(mod, exp, sig);
                break;
            case 3072:
                result = await contract.recoverHashRSA3072(mod, exp, sig);
                break;
            case 4096:
                result = await contract.recoverHashRSA4096(mod, exp, sig);
                break;
            default:
                console.log(test);
                throw new Error(`unknown key size`)
        }

        // Check the result
        if (!result.success && result.hash !== ("0x" + test.hash)) {
            pass++;
        } else {
            fail++;
            console.log(test.size, test.exponent, test.hash, result);
        }
    }

    // Print some stats
    console.log({ pass, fail })
    console.log("");
    for (const key of Object.keys(stats)) {
        const stat = stats[key];
        console.log(key, "=>", stat.totalGas / stat.count, "gas");
    }

    return (fail == 0);

})().then((result) => {
    process.exit(result ? 0: 1);
}, (error) => {
    console.log(error);
    process.exit(1);
});
