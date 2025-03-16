"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateRsaKeyPair = generateRsaKeyPair;
exports.exportPubKey = exportPubKey;
exports.exportPrvKey = exportPrvKey;
exports.importPubKey = importPubKey;
exports.importPrvKey = importPrvKey;
exports.rsaEncrypt = rsaEncrypt;
exports.rsaDecrypt = rsaDecrypt;
exports.createRandomSymmetricKey = createRandomSymmetricKey;
exports.exportSymKey = exportSymKey;
exports.importSymKey = importSymKey;
exports.symEncrypt = symEncrypt;
exports.symDecrypt = symDecrypt;
const crypto_1 = require("crypto");
// #############
// ### Utils ###
// #############
// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer) {
    return Buffer.from(buffer).toString("base64");
}
// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64) {
    var buff = Buffer.from(base64, "base64");
    return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}
const { subtle } = globalThis.crypto;
const publicExponent = new Uint8Array([1, 0, 1]);
async function generateRsaKeyPair() {
    const { publicKey, privateKey, } = await subtle.generateKey({
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent,
        hash: "SHA-256",
    }, true, ['encrypt', 'decrypt']);
    return { publicKey, privateKey };
}
// Export a crypto public key to a base64 string format
async function exportPubKey(key) {
    return arrayBufferToBase64(await crypto_1.webcrypto.subtle.exportKey("spki", key));
}
// Export a crypto private key to a base64 string format
async function exportPrvKey(key) {
    if (!key)
        return null;
    return arrayBufferToBase64(await crypto_1.webcrypto.subtle.exportKey("pkcs8", key));
}
// Import a base64 string public key to its native format
async function importPubKey(strKey) {
    const key = await subtle.importKey("spki", base64ToArrayBuffer(strKey), {
        name: "RSA-OAEP",
        hash: "SHA-256"
    }, true, ["encrypt"]);
    return key;
}
// Import a base64 string private key to its native format
async function importPrvKey(strKey) {
    const key = await subtle.importKey("pkcs8", base64ToArrayBuffer(strKey), {
        name: "RSA-OAEP",
        hash: "SHA-256"
    }, true, ["decrypt"]);
    return key;
}
// Encrypt a message using an RSA public key
async function rsaEncrypt(b64Data, strPublicKey) {
    const publicKey = await importPubKey(strPublicKey);
    const data = base64ToArrayBuffer(b64Data);
    const encrypted = await subtle.encrypt({ name: "RSA-OAEP" }, publicKey, data);
    return arrayBufferToBase64(encrypted);
}
// Decrypts a message using an RSA private key
async function rsaDecrypt(data, privateKey) {
    const encryptedData = base64ToArrayBuffer(data);
    const decrypted = await subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedData);
    return arrayBufferToBase64(decrypted);
}
// ######################
// ### Symmetric keys ###
// ######################
// Generates a random symmetric key
async function createRandomSymmetricKey() {
    return await subtle.generateKey({
        name: "AES-CBC",
        length: 256
    }, true, ["encrypt", "decrypt"]);
}
// Export a crypto symmetric key to a base64 string format
async function exportSymKey(key) {
    const exported = await subtle.exportKey("raw", key);
    return arrayBufferToBase64(exported);
}
// Import a base64 string format to its crypto native format
async function importSymKey(strKey) {
    const keyData = base64ToArrayBuffer(strKey);
    return await subtle.importKey("raw", keyData, {
        name: "AES-CBC",
        length: 256
    }, true, ["encrypt", "decrypt"]);
}
// Encrypt a message using a symmetric key
async function symEncrypt(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(16)); // AES-CBC utilise un IV de 16 bytes
    const encodedData = new TextEncoder().encode(data);
    const encrypted = await subtle.encrypt({
        name: "AES-CBC",
        iv: iv
    }, key, encodedData);
    // Combine IV and encrypted data
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return arrayBufferToBase64(combined);
}
// Decrypt a message using a symmetric key
async function symDecrypt(strKey, encryptedData) {
    const key = await importSymKey(strKey);
    const combined = base64ToArrayBuffer(encryptedData);
    const combinedArray = new Uint8Array(combined);
    // Extract IV and encrypted data
    const iv = combinedArray.slice(0, 16);
    const data = combinedArray.slice(16);
    const decrypted = await subtle.decrypt({
        name: "AES-CBC",
        iv: iv
    }, key, data);
    return new TextDecoder().decode(decrypted);
}
