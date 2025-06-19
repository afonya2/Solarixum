const PROT_NAME = 'Solarixum Protocol';
const PROT_VER = '0.1.0';

function generateRandomString(length: number): string {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}
function dataToBase64(data: ArrayBuffer | Uint8Array): string {
    return btoa(
        String.fromCharCode(...new Uint8Array(data))
    );
}
function base64ToData(base64: string): Uint8Array {
    return new Uint8Array(
        atob(base64)
            .split("")
            .map((c) => c.charCodeAt(0))
    );
}
function base64ToArray(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}
async function passwordToIV(password: string): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(password));
    return new Uint8Array(hashBuffer.slice(0, 16));
}
async function derivePasswordKey(password: string): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
    return await crypto.subtle.deriveKey({
        name: "PBKDF2",
        salt: await passwordToIV(password),
        iterations: 100000,
        hash: "SHA-256"
    }, keyMaterial, { name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt"]);
}
async function decryptPrivateKey(): Promise<CryptoKey | null> {
    let key = localStorage.getItem("privateKey");
    let passwordKey = localStorage.getItem("passwordKey");
    if (!key) {
        console.error("No private key found in local storage.");
        return null;
    }
    if (!passwordKey) {
        console.error("No password hash found in local storage.");
        return null;
    }
    let iv = await passwordToIV(passwordKey);
    let keyBuffer = await crypto.subtle.importKey("raw", base64ToData(passwordKey), { name: "AES-CBC" }, false, ["decrypt"]);
    let encryptedPrivKey = base64ToData(key);
    let decryptedPrivKey = await crypto.subtle.decrypt(
        {
            name: "AES-CBC",
            iv: iv,
        },
        keyBuffer,
        encryptedPrivKey
    );
    return await crypto.subtle.importKey("pkcs8", decryptedPrivKey, { name: "RSA-OAEP", hash: "SHA-256" }, true, [
        "decrypt",
    ]);
}
async function encryptPrivateKey(key: CryptoKey) {
    let passwordKey = localStorage.getItem("passwordKey");
    if (!key) {
        console.error("No private key found in local storage.");
        return null;
    }
    if (!passwordKey) {
        console.error("No password key found in local storage.");
        return null;
    }
    let iv = await passwordToIV(passwordKey);
    let keyBuffer = await crypto.subtle.importKey("raw", base64ToData(passwordKey), { name: "AES-CBC" }, false, ["encrypt"]);
    let exportedKey = await crypto.subtle.exportKey("pkcs8", key);
    let encryptedPrivKey = await crypto.subtle.encrypt(
        {
            name: "AES-CBC",
            iv: iv,
        },
        keyBuffer,
        exportedKey
    );
    localStorage.setItem("privateKey", dataToBase64(encryptedPrivKey));
}
async function checkLogin(): Promise<{ username: string; createdAt: string } | boolean> {
    const token = localStorage.getItem("token");
    if (!token) {
        return false;
    }
    let req = await fetch("/api/me", {
        method: "GET",
        headers: {
            "Content-Type": "application/json",
            "Authorization": token,
            "protocol": PROT_NAME,
            "protocol-version": PROT_VER
        }
    })
    let res = await req.json();
    if (res.ok) {
        return {
            username: res.username,
            createdAt: res.createdAt
        };
    } else {
        return false;
    }
}

export default {
    generateRandomString,
    dataToBase64,
    base64ToData,
    base64ToArray,
    passwordToIV,
    derivePasswordKey,
    encryptPrivateKey,
    decryptPrivateKey,
    checkLogin
}