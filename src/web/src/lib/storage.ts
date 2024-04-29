import { decodeSuiPrivateKey } from "@mysten/sui.js/cryptography";
import { Ed25519Keypair } from "@mysten/sui.js/keypairs/ed25519";
import { RPC_ENDPOINTS } from "@polymedia/spam-sdk";
import { NetworkName } from "@polymedia/suits";

const keySecretKey = "spam.secretKey";
const keyRpcUrls = "spam.rpcUrls";

/* Key pair */

export function loadKeypairFromStorage(): Ed25519Keypair {
    const secretKey = localStorage.getItem(keySecretKey);
    let pair: Ed25519Keypair;
    if (!secretKey) {
        pair = new Ed25519Keypair();
        saveKeypairToStorage(pair);
    } else {
        pair = pairFromSecretKey(secretKey);
    }
    return pair;
}

export function saveKeypairToStorage(pair: Ed25519Keypair): void {
    localStorage.setItem(keySecretKey, pair.getSecretKey());
}

export function pairFromSecretKey(secretKey: string): Ed25519Keypair {
    const parsedPair = decodeSuiPrivateKey(secretKey);
    return Ed25519Keypair.fromSecretKey(parsedPair.secretKey);
}

/* RPC URLs */

export type RpcUrl = {
    url: string,
    enabled: boolean,
};

export function loadRpcUrlsFromStorage(network: NetworkName): RpcUrl[] {
    const rawRpcUrls = localStorage.getItem(keyRpcUrls);
    let rpcUrls: RpcUrl[];
    if (!rawRpcUrls) {
        rpcUrls = getDefaultRpcUrls(network);
        saveRpcUrlsToStorage(rpcUrls);
    } else {
        rpcUrls = JSON.parse(rawRpcUrls) as RpcUrl[];
    }
    return rpcUrls;
}

export function saveRpcUrlsToStorage(rpcUrls: RpcUrl[]): void {
    localStorage.setItem(keyRpcUrls, JSON.stringify(rpcUrls));
}

function getDefaultRpcUrls(network: NetworkName): RpcUrl[] {
    return RPC_ENDPOINTS[network].map(url => {
        return { url, enabled: true };
    });
}
