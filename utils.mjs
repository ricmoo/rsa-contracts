import { readdirSync, readFileSync } from "node:fs";

import { basename, dirname, resolve as _resolve } from "node:path";
import { fileURLToPath } from 'node:url';

import { Interface } from "ethers";
import solc from "solc";


const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);


export const ROOT = _resolve(__dirname);

// Resolve a path based on project root
export function resolve(...args) {
    return _resolve.apply(null, [ ROOT, ...args ]);
}

/*
export function loadContract(name) {
    const abi = JSON.parse(readFileSync(`./build/${ name }.abi`).toString());
    const bytecode = readFileSync(`./build/${ name }.bin`).toString();
    return { abi, bytecode };
}
*/

// List all contracts in %%source%%
function getContracts(source) {
    source = source.replace(/\/\/.*/g, "");
    source = source.replace(/\/\*(.|\n)*?\*\//g, "/* [removed] */");
    source = source.replace(/"([^\\"]|(\\.))*"/g, '""');
    source = source.replace(/\s+/g, " ");
    const result = [ ];
    source.replace(/contract ([a-zA-Z_][a-zA-Z0-9_]*) ?{/g, /* fix:} */(_all, name) => {
        result.push(name);
    });
    return result;
}

// Search the contracts/ folder and return the filename for contract %%name%%.
export function findContract(name) {
    const result = [ ];
    for (const filename of readdirSync(resolve("contracts"))) {
        if (!filename.endsWith(".sol")) { continue; }

        const path = resolve("contracts", filename);

        // Get the normalized contract source:
        // - no // comments
        // - no /* */ comments
        // - no strings contents
        // - all whitespace is a single space
        const contracts = getContracts(readFileSync(path).toString());
        if (contracts.indexOf(name) >= 0) { result.push(path); }
    }

    if (result.length == 0) { throw new Error(`contract not found: ${ name }`); }
    if (result.length > 1) {
        throw new Error(`multiple contracts found: ${ result.map(n => JSON.stringify(n)).join(", ") }`);
    }
    return result[0];
}

// Search the contracts/ folder and compile the contract with %%name%%.
export function compile(name) {
    const path = findContract(name);

    const filename = basename(path);
    const source = readFileSync(path).toString();

    // Solidity compiler input format (JSON)
    const input = {
        language: "Solidity",
        sources: {
            [filename]: { content: source }
        },
        settings: {
            optimizer: {
                enabled: true,
                runs: 200
            },
            outputSelection: {
                "*": {
                    "*": [ "abi", "evm.bytecode" ]
                }
            }
        }
    };

    // Compile
    const output = JSON.parse(solc.compile(JSON.stringify(input), {
        import: (path) => {
            try {
                return {
                    contents: readFileSync(resolve("contracts", path)).toString()
                }
            } catch (e) {
                return { error: `File not found: ${ path }` };
            }
        }
    }));

    if (output.errors) {
        output.errors.forEach(e => {
            console.log(e.formattedMessage);
            console.log();
        });
        throw new Error(`errors during compilation`);
    }

    // Access compiled data
    const contract = output.contracts[filename][name];
    if (!contract) {
        throw new Error(`contract not compiled: ${ filename }:${ name }`);
    }

    return {
      abi: (new Interface(contract.abi)).format(),
      bytecode: "0x" + contract.evm.bytecode.object
    };
}



export function splitBytes32(value) {
    if (value.startsWith("0x")) { value = value.substring(2); }

    const result = [ ];
    for (let i = 0; i < value.length; i += 64) {
        result.push("0x" + value.substring(i, i + 64));
    }

    return result;
}

