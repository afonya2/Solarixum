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
    const hash = await crypto.subtle.digest("SHA-256", encoder.encode(password));
    return await crypto.subtle.importKey("raw", hash, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
}
async function decryptPrivateKey(password: string): Promise<CryptoKey | null> {
    let key = localStorage.getItem("privateKey");
    if (!key) {
        console.error("No private key found in local storage.");
        return null;
    }
    let iv = await passwordToIV(password);
    let keyBuffer = await derivePasswordKey(password);
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

export default {
    generateRandomString,
    dataToBase64,
    base64ToData,
    base64ToArray,
    passwordToIV,
    derivePasswordKey,
    decryptPrivateKey
}