/**
 * Simulated Cryptography Utilities for Intrusion-Aware Data Access
 * 
 * Note: these are NOT real cryptographic functions. They are simulations
 * designed to demonstrate the concept of "Ciphertext" vs "Plaintext"
 * and the mechanism of key release.
 */

// Simulates AES Encryption by converting text to Base64 and reversing it
export const simulateEncrypt = (text) => {
    if (!text) return "";
    return btoa(text).split('').reverse().join('') + "==Encrypted";
};

// Simulates AES Decryption
export const simulateDecrypt = (cipherText) => {
    if (!cipherText || !cipherText.endsWith("==Encrypted")) return null;
    const clean = cipherText.replace("==Encrypted", "").split('').reverse().join('');
    try {
        return atob(clean);
    } catch (e) {
        return "Error: Decryption Failed";
    }
};

// Simulates SHA-256 Hashing (One-way)
export const simulateHash = async (text) => {
    const msgBuffer = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

export const MOCK_DATA = "CONFIDENTIAL: This is the protected core system data. Access is only granted to trusted entities.";
