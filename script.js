function aesEncrypt() {
    let plaintext = document.getElementById("aes-plaintext").value;
    if (plaintext === "") {
        alert("Please enter text to encrypt!");
        return;
    }
    let encrypted = btoa(plaintext);  // Mock AES encryption
    document.getElementById("aes-encrypted").value = encrypted;
}

function aesDecrypt() {
    let encryptedText = document.getElementById("aes-encrypted").value;
    if (encryptedText === "") {
        alert("No encrypted text found!");
        return;
    }
    let decrypted = atob(encryptedText);
    document.getElementById("aes-decrypted").value = decrypted;
}

// Proper Hill Cipher encryption
function hillEncrypt() {
    let plaintext = document.getElementById("hill-plaintext").value;
    let key = document.getElementById("hill-key").value;
    if (plaintext === "" || key === "") {
        alert("Please enter text and key to encrypt!");
        return;
    }

    let keyMatrix = key.split(',').map(Number);
    if (keyMatrix.length !== 4) {
        alert("Invalid key matrix! Enter 4 numbers separated by commas.");
        return;
    }

    let textVector = plaintext.toUpperCase().split('').map(c => c.charCodeAt(0) - 65);
    if (textVector.length % 2 !== 0) textVector.push(23); // Padding with 'X'

    let encryptedText = '';
    for (let i = 0; i < textVector.length; i += 2) {
        let x = textVector[i], y = textVector[i + 1];
        let enc1 = (keyMatrix[0] * x + keyMatrix[1] * y) % 26;
        let enc2 = (keyMatrix[2] * x + keyMatrix[3] * y) % 26;
        encryptedText += String.fromCharCode(enc1 + 65) + String.fromCharCode(enc2 + 65);
    }

    document.getElementById("hill-encrypted").value = encryptedText;
}

// Hill Cipher decryption
function hillDecrypt() {
    let encryptedText = document.getElementById("hill-encrypted").value;
    let key = document.getElementById("hill-key").value;
    if (encryptedText === "" || key === "") {
        alert("Please enter encrypted text and key to decrypt!");
        return;
    }

    let keyMatrix = key.split(',').map(Number);
    if (keyMatrix.length !== 4) {
        alert("Invalid key matrix! Enter 4 numbers separated by commas.");
        return;
    }

    let det = (keyMatrix[0] * keyMatrix[3] - keyMatrix[1] * keyMatrix[2]) % 26;
    if (det < 0) det += 26;

    let invDet = -1;
    for (let i = 0; i < 26; i++) {
        if ((det * i) % 26 === 1) {
            invDet = i;
            break;
        }
    }

    if (invDet === -1) {
        alert("Key matrix is not invertible!");
        return;
    }

    let inverseMatrix = [
        (keyMatrix[3] * invDet) % 26,
        (-keyMatrix[1] * invDet) % 26,
        (-keyMatrix[2] * invDet) % 26,
        (keyMatrix[0] * invDet) % 26
    ].map(num => (num + 26) % 26);

    let textVector = encryptedText.toUpperCase().split('').map(c => c.charCodeAt(0) - 65);
    let decryptedText = '';

    for (let i = 0; i < textVector.length; i += 2) {
        let x = textVector[i], y = textVector[i + 1];
        let dec1 = (inverseMatrix[0] * x + inverseMatrix[1] * y) % 26;
        let dec2 = (inverseMatrix[2] * x + inverseMatrix[3] * y) % 26;
        decryptedText += String.fromCharCode(dec1 + 65) + String.fromCharCode(dec2 + 65);
    }

    document.getElementById("hill-decrypted").value = decryptedText;
}
// Proper AES Encryption and Decryption using Web Crypto API
async function generateAESKey() {
    const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    return key;
}

async function aesEncrypt() {
    let plaintext = document.getElementById("aes-plaintext").value;
    if (plaintext === "") {
        alert("Please enter text to encrypt!");
        return;
    }

    const key = await generateAESKey();
    const iv = crypto.getRandomValues(new Uint8Array(12)); // Initialization vector

    const encodedText = new TextEncoder().encode(plaintext);
    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedText
    );

    const encryptedArray = new Uint8Array(encryptedBuffer);
    const encryptedBase64 = btoa(String.fromCharCode(...encryptedArray));
    const ivBase64 = btoa(String.fromCharCode(...iv));

    document.getElementById("aes-encrypted").value = `${ivBase64}:${encryptedBase64}`;

    // Storing key and IV temporarily for decryption
    window.aesKey = key;
    window.aesIV = iv;
}

async function aesDecrypt() {
    const encryptedData = document.getElementById("aes-encrypted").value;
    if (encryptedData === "") {
        alert("No encrypted text found!");
        return;
    }

    const [ivBase64, encryptedBase64] = encryptedData.split(":");
    const iv = new Uint8Array(atob(ivBase64).split('').map(c => c.charCodeAt(0)));
    const encryptedArray = new Uint8Array(atob(encryptedBase64).split('').map(c => c.charCodeAt(0)));

    try {
        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            window.aesKey,
            encryptedArray
        );

        const decryptedText = new TextDecoder().decode(decryptedBuffer);
        document.getElementById("aes-decrypted").value = decryptedText;
    } catch (error) {
        alert("Decryption failed! Invalid key or corrupted data.");
    }
}
