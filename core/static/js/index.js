const socket = io({ autoConnect: false }); // Initialize a socket connection but prevent it from automatically connecting until explicitly triggered.
let privateKey, publicKey; // Declare variables to hold the RSA private and public keys.
var clientKeys = JSON.parse(localStorage.getItem('clientKeys')) || {}; // Retrieve previously saved client keys from localStorage or initialize an empty object if no data exists.
var username, chatClient, chatClientPK; // Define variables for the current username, the chat client, and the public key of the chat client.
var isCurrentUser = true; // A flag to track whether the current user is active or sending messages in a conversation.

// Define a function to save client keys to localStorage for persistent storage. The `clientKeys` object is serialized to a JSON string and stored.
function saveClientKeys() {
    localStorage.setItem('clientKeys', JSON.stringify(clientKeys));
}

// Define a function to save the public key to localStorage for later retrieval. The `publicKey` variable is stored as a string.
function savePublicKey() {
    localStorage.setItem('publicKey', publicKey);
}

// Define a function to load the public key from localStorage. The value is retrieved and assigned to the `publicKey` variable.
function loadPublicKey() {
    publicKey = localStorage.getItem('publicKey');
}

// Define an asynchronous function to save the private key to localStorage securely. The private key is exported in PKCS8 format, converted to a Base64 string, encrypted with a password, and then stored in localStorage.
async function savePrivateKey() {
    const exportedPrivateKey = await window.crypto.subtle.exportKey("pkcs8", privateKey);
    const privateKeyBase64 = arrayBufferToBase64(exportedPrivateKey);
    const encryptedPrivateKey = await encryptPrivateKey(privateKeyBase64, 'your-password'); // Encrypt the private key using a password.
    localStorage.setItem('privateKey', encryptedPrivateKey);
}

// Define an asynchronous function to load the private key from localStorage securely. The encrypted private key is retrieved, decrypted with a password, and imported back into the Web Crypto API as a usable key object.
async function loadPrivateKey() {
    const encryptedPrivateKey = localStorage.getItem('privateKey'); // Retrieve the encrypted private key from localStorage.
    if (encryptedPrivateKey) {
        const privateKeyBase64 = await decryptPrivateKey(encryptedPrivateKey, 'your-password'); // Decrypt the private key using the provided password.
        const privateKeyArrayBuffer = base64ToArrayBuffer(privateKeyBase64); // Convert the Base64 string to an ArrayBuffer.
        privateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            privateKeyArrayBuffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["decrypt"] // Specify the usage of the private key for decryption purposes.
        );
        console.log("Private key successfully loaded.");
    } else {
        console.log("No private key found in localStorage."); // Log a message if no private key is found in localStorage.
    }
}

// Define an asynchronous function to encrypt the private key using AES-GCM. The private key in Base64 format is encrypted with a derived password-based key and returned as a Base64 string.
async function encryptPrivateKey(privateKeyBase64, password) {
    const passwordKey = await getPasswordKey(password); // Derive a cryptographic key from the provided password.
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Generate a random initialization vector (IV) for the encryption.
    const encryptedContent = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        passwordKey,
        new TextEncoder().encode(privateKeyBase64) // Encode the private key as a Uint8Array for encryption.
    );
    const encryptedContentArr = new Uint8Array(encryptedContent); // Convert the encrypted content to a Uint8Array.
    const buff = new Uint8Array(iv.byteLength + encryptedContentArr.byteLength); // Create a buffer to hold both the IV and the encrypted content.
    buff.set(iv, 0); // Append the IV at the beginning of the buffer.
    buff.set(encryptedContentArr, iv.byteLength); // Append the encrypted content after the IV.
    return arrayBufferToBase64(buff); // Convert the combined buffer to a Base64 string and return it.
}

// Define an asynchronous function to decrypt the private key using AES-GCM. The function extracts the IV and encrypted content from the provided Base64 string, decrypts it using a password-derived key, and returns the decrypted private key in Base64 format.
async function decryptPrivateKey(encryptedPrivateKeyBase64, password) {
    const encryptedPrivateKeyBuff = base64ToArrayBuffer(encryptedPrivateKeyBase64); // Convert the Base64 string to an ArrayBuffer.
    const iv = encryptedPrivateKeyBuff.slice(0, 12); // Extract the IV from the first 12 bytes of the buffer.
    const data = encryptedPrivateKeyBuff.slice(12); // Extract the encrypted content starting from the 13th byte.
    const passwordKey = await getPasswordKey(password); // Derive a cryptographic key from the provided password.
    const decryptedContent = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        passwordKey,
        data // Use the encrypted content for decryption.
    );
    return new TextDecoder().decode(decryptedContent); // Decode the decrypted content into a string and return it.
}

// Define an asynchronous function to derive a cryptographic key from a password using PBKDF2. The function uses a predefined salt, iteration count, and hash algorithm to produce a 256-bit AES key.
async function getPasswordKey(password) {
    const enc = new TextEncoder(); // Create a TextEncoder to encode the password into a Uint8Array.
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" }, // Specify PBKDF2 as the key derivation algorithm.
        false,
        ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode("salt"), // Use a predefined salt for key derivation.
            iterations: 100000, // Specify the number of iterations for key strengthening.
            hash: "SHA-256" // Use SHA-256 as the hash algorithm for PBKDF2.
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 }, // Define the derived key as a 256-bit AES key for GCM mode.
        false,
        ["encrypt", "decrypt"] // Grant the derived key permissions for encryption and decryption.
    );
}

// Add an event listener to the document that runs when the DOM content is fully loaded. This function sets up form handling for all forms on the page.
document.addEventListener('DOMContentLoaded', function () {
    console.log("Page loaded. Initializing form event handlers...");

    // Select all forms on the page and iterate over each form.
    const forms = document.querySelectorAll('form');

    // Add a submit event listener to each form to handle custom submission behavior.
    forms.forEach(form => {
        form.addEventListener('submit', function (event) {
            event.preventDefault(); // Prevent the default form submission behavior, allowing custom handling.

            const formData = new FormData(form); // Serialize the form data into a FormData object.
            const email = formData.get('email'); // Extract the email field value from the form.
            const subject = encodeURIComponent(formData.get('subject')); // Encode the subject field value for use in a URL.
            const body = encodeURIComponent(formData.get('body')); // Encode the body field value for use in a URL.

            const mailtoLink = `mailto:${email}?subject=${subject}&body=${body}`; // Construct a mailto link with the form data.

            window.location.href = mailtoLink; // Open the mailto link to initiate an email client.

            form.reset(); // Reset the form fields to their default state after submission.
        });
    });
});
