const socket = io({ autoConnect: false }); // Initialize a socket connection with autoConnect set to false.
let privateKey, publicKey; // Declare variables for the user's RSA private and public keys.

var clientKeys = JSON.parse(localStorage.getItem('clientKeys')) || {}; // Retrieve client keys from localStorage or initialize an empty object.
var username, chatClient, chatClientPK; // Declare variables for the current user and chat client data.
var isCurrentUser = true; // Flag to indicate whether the current user is active.

// Function to save client keys to localStorage
function saveClientKeys() {
    localStorage.setItem('clientKeys', JSON.stringify(clientKeys)); // Store the clientKeys object as a JSON string in localStorage.
}

// Function to save the public key to localStorage
function savePublicKey() {
    localStorage.setItem('publicKey', publicKey); // Save the public key as a string in localStorage.
}

// Function to load the public key from localStorage
function loadPublicKey() {
    publicKey = localStorage.getItem('publicKey'); // Retrieve the public key from localStorage.
}

// Function to save the private key to localStorage securely
async function savePrivateKey() {
    const exportedPrivateKey = await window.crypto.subtle.exportKey("pkcs8", privateKey); // Export the private key in PKCS8 format.
    const privateKeyBase64 = arrayBufferToBase64(exportedPrivateKey); // Convert the private key to a Base64 string.
    const encryptedPrivateKey = await encryptPrivateKey(privateKeyBase64, 'your-password'); // Encrypt the private key with a password.
    localStorage.setItem('privateKey', encryptedPrivateKey); // Save the encrypted private key in localStorage.
}

// Function to load the private key from localStorage securely
async function loadPrivateKey() {
    const encryptedPrivateKey = localStorage.getItem('privateKey'); // Retrieve the encrypted private key from localStorage.
    if (encryptedPrivateKey) {
        const privateKeyBase64 = await decryptPrivateKey(encryptedPrivateKey, 'your-password'); // Decrypt the private key using the password.
        const privateKeyArrayBuffer = base64ToArrayBuffer(privateKeyBase64); // Convert the Base64 string to an ArrayBuffer.
        privateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            privateKeyArrayBuffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256" // Use SHA-256 as the hashing algorithm.
            },
            true,
            ["decrypt"] // Grant decryption permissions to the key.
        );
        console.log("Private key successfully loaded."); // Log success message.
    } else {
        console.log("No private key found in localStorage."); // Log message if no key is found.
    }
}

// Function to encrypt the private key with AES-GCM
async function encryptPrivateKey(privateKeyBase64, password) {
    const passwordKey = await getPasswordKey(password); // Derive a key from the provided password.
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Generate a random initialization vector (IV).
    const encryptedContent = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv // Use the IV for encryption.
        },
        passwordKey,
        new TextEncoder().encode(privateKeyBase64) // Encode the private key to a Uint8Array.
    );
    const encryptedContentArr = new Uint8Array(encryptedContent); // Convert the encrypted content to a Uint8Array.
    const buff = new Uint8Array(iv.byteLength + encryptedContentArr.byteLength); // Concatenate the IV and encrypted content.
    buff.set(iv, 0);
    buff.set(encryptedContentArr, iv.byteLength);
    return arrayBufferToBase64(buff); // Convert the result to a Base64 string.
}

// Function to decrypt the private key with AES-GCM
async function decryptPrivateKey(encryptedPrivateKeyBase64, password) {
    const encryptedPrivateKeyBuff = base64ToArrayBuffer(encryptedPrivateKeyBase64); // Convert the Base64 string to an ArrayBuffer.
    const iv = encryptedPrivateKeyBuff.slice(0, 12); // Extract the IV from the buffer.
    const data = encryptedPrivateKeyBuff.slice(12); // Extract the encrypted content.
    const passwordKey = await getPasswordKey(password); // Derive a key from the provided password.
    const decryptedContent = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv // Use the IV for decryption.
        },
        passwordKey,
        data // Decrypt the data.
    );
    return new TextDecoder().decode(decryptedContent); // Decode and return the decrypted content.
}

// Function to derive a key from a password
async function getPasswordKey(password) {
    const enc = new TextEncoder(); // Create a TextEncoder instance.
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password), // Encode the password to a Uint8Array.
        { name: "PBKDF2" }, // Use PBKDF2 for key derivation.
        false,
        ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode("salt"), // Use a fixed salt for derivation.
            iterations: 100000, // Set the number of iterations.
            hash: "SHA-256" // Use SHA-256 as the hashing algorithm.
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 }, // Derive a 256-bit AES key.
        false,
        ["encrypt", "decrypt"] // Grant encryption and decryption permissions.
    );
}

// Function to handle form submission events
document.addEventListener('DOMContentLoaded', function () {
    console.log("Page loaded. Initializing form event handlers..."); // Log page load event.

    // Select all forms on the page
    const forms = document.querySelectorAll('form');

    // Add a submit event listener to each form
    forms.forEach(form => {
        form.addEventListener('submit', function (event) {
            event.preventDefault(); // Prevent default form submission.

            const formData = new FormData(form); // Serialize form data.
            const email = formData.get('email'); // Get the email value.
            const subject = encodeURIComponent(formData.get('subject')); // Encode the subject.
            const body = encodeURIComponent(formData.get('body')); // Encode the body.

            const mailtoLink = `mailto:${email}?subject=${subject}&body=${body}`; // Create a mailto link.
            window.location.href = mailtoLink; // Open the mailto link.
            form.reset(); // Reset the form fields.
        });
    });
});

// Function to initialize and load user-specific data on page load
document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById("logout-btn").value = "Logout-" + userData.Username; // Update logout button text with the username.

    // Load private and public keys from localStorage
    await loadPrivateKey(); 
    loadPublicKey();

    // Re-establish connection using the clientKeys stored in localStorage
    if (Object.keys(clientKeys).length > 0) {
        loadAvailableFriends(); // Load friends available for connection.
        loadConReceiveFriends(); // Load received connection requests.
        loadAccepetdFriends(); // Load accepted friends list.
    }

    // Handle notification when a connection request is sent
    socket.on('email_send_notify', function (data) {
        try {
            clientKeys[data['sender']].status = "con_recv"; // Update the sender's status to connection received.
            saveClientKeys(); // Save the updated client keys.
            loadConReceiveFriends(); // Refresh the received connections list.
            loadAvailableFriends(); // Refresh the available friends list.
        } catch (error) {
            console.error("Error message error:", error); // Log errors.
        }
    });

    // Handle notification when a connection request reply is received
    socket.on('email_reply_notify', function (data) {
        try {
            clientKeys[data['sender']].status = "con_reply_recv"; // Update the sender's status to reply received.
            saveClientKeys(); // Save the updated client keys.
            loadAvailableFriends(); // Refresh the available friends list.
            loadConReceiveFriends(); // Refresh the received connections list.
        } catch (error) {
            console.error("Error message error:", error); // Log errors.
        }
    });

    // Handle incoming messages
    socket.on('message', async (data) => {
        try {
            let ul = document.getElementById("chat-msg"); // Select the chat messages list.
            if (chatClient != data["sender"]) {
                displaySelectFriendMessage(false); // Notify that a new sender's message is received.
                let li = document.createElement("li");
                li.appendChild(document.createTextNode(`Chat with - ${data["sender"]}`)); // Display sender's name.
                li.classList.add("center_user"); // Add styling class.
                ul.appendChild(li); // Append the message.
                ul.scrollTop = ul.scrollHeight; // Scroll to the bottom of the chat.

                chatClient = data["sender"]; // Update current chat client.
                chatClientPK = clientKeys[data["sender"]].publicKey; // Retrieve sender's public key.
            }

            isCurrentUser = false; // Indicate the message is not from the current user.

            console.log("Sender------------", data["sender"]); // Log sender information.
            console.log("Sender Encrypted Message------------", data["message"]); // Log encrypted message.

            let decryptedMessage = await decryptRSAOAEP(data["message"], privateKey); // Decrypt the received message.
            console.log("Sender Decrypted Message------------", decryptedMessage); // Log decrypted message.

            const li = document.createElement("li");
            li.appendChild(document.createTextNode(`Friend: ${decryptedMessage}`)); // Display decrypted message.
            li.classList.add("left_user"); // Add styling class.
            ul.appendChild(li); // Append the message to the list.
            ul.scrollTop = ul.scrollHeight; // Scroll to the bottom of the chat.
        } catch (error) {
            console.error("Error message error:", error); // Log errors.
        }
    });
});
