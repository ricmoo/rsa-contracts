import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

import { ethers } from "ethers";


function run(progname, args) {
    if (args == null) { args = [ ]; }

    const child = spawnSync(progname, args, { });
    if (child.status) {
        console.log(child);
        throw new Error(`running "${ progname } ${ args.join(" ") }" failed`);
    }

    return child.stdout.toString();
}

function randInt(seed, lo, hi) {
    return Number(BigInt(ethers.id(seed)) % BigInt(hi - lo) + BigInt(lo));
}

function generateTest(size, exp, name) {

    const runGenPrivkey = run("openssl", [
      "genpkey", "-algorithm", "RSA", "-out", "privkey.pem",
      "-pkeyopt", `rsa_keygen_bits:${ size }`,
      "-pkeyopt", `rsa_keygen_pubexp:${ exp }`
    ]);
    const privkey = readFileSync("privkey.pem").toString();

    const runExtractPubkey = run("openssl", [
      "rsa", "-in", "privkey.pem", "-pubout", "-out", "pubkey.pem"
    ]);

    const runGetPubkey = run("openssl", [
      "rsa", "-pubin", "-in", "pubkey.pem", "-noout", "-text"
    ]);

    const exponent = parseInt(runGetPubkey.match(/Exponent: ([0-9]+)/m)[1]);

    // For some reason, the modulus always has an extra 00 prefix
    const modulus = runGetPubkey.match(/Modulus:\n([0-9a-f:\n\t ]+)/)[1].
      replace(/[\n\t :]/g, "").substring(2);

    const words = [ ];
    const length = randInt(name + ".length", 3, 20);
    for (let i = 0; i < 10; i++) {
        const index = randInt(name + `:word-${ i }`, 0, 2048);
        const word = ethers.wordlists.en.getWord(index);
        words.push(word);
    }

    const text = "test-text: " + words.join("-");
    writeFileSync("data.txt", text);

    const hash = ethers.sha256(ethers.toUtf8Bytes(text)).substring(2);

    const runSign = run("openssl", [
        "dgst", "-sha256", "-sign", "privkey.pem", "-out",
        "signature.bin", "data.txt"
    ]);
    const signature = readFileSync("signature.bin").toString("hex");

    return { size, privkey, exponent, modulus, text, hash, signature };
}


(async function() {
    const tests = [ ];
    for (const size of [ 1024, 2048, 3072, 4096 ]) {
        for (const exp of [ 3, 0x10001 ]) {
            for (let i = 0; i < 32; i++) {
                console.log({ size, exp, i });
                const test = generateTest(size, exp, `random-${ size }-${ exp }:${ i }`);
                tests.push(test);
            }
        }
    }

    writeFileSync("../testcases.json", JSON.stringify(tests));
})();
