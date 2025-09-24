import { readFileSync } from "node:fs";

export function splitBytes32(value) {
    if (value.startsWith("0x")) { value = value.substring(2); }

    const result = [ ];
    for (let i = 0; i < value.length; i += 64) {
        result.push("0x" + value.substring(i, i + 64));
    }

    return result;
}


export function loadJson(filename) {
    return JSON.parse(readFileSync(filename));
}

export function readContract(name) {
    return loadJson(`./build/${ name }.json`);
}
