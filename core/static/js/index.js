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

/**
 * Initializes event listeners and loads user-specific data upon the DOM's content being fully loaded.
 * This includes setting up logout functionality, loading cryptographic keys, 
 * and establishing connections to handle notifications and chat messages.
 */
document.addEventListener('DOMContentLoaded', async () => {
    // Sets the value of the logout button to display the username for the current session.
    document.getElementById("logout-btn").value = "Logout-" + userData.Username;

    // Loads the private and public cryptographic keys from local storage to enable secure communication.
    await loadPrivateKey();
    loadPublicKey();

    // If there are saved client keys, reload the friend lists for various statuses (available, received, accepted).
    if (Object.keys(clientKeys).length > 0) {
        loadAvailableFriends();
        loadConReceiveFriends();
        loadAccepetdFriends();
    }

    /**
     * Listens for a notification about an email being sent and updates the client keys accordingly.
     * Updates the list of available and connection-received friends.
     */
    socket.on('email_send_notify', function (data) {
        try {
            clientKeys[data['sender']].status = "con_recv";
            saveClientKeys();
            loadConReceiveFriends();
            loadAvailableFriends();
        } catch (error) {
            console.error("Error handling email_send_notify:", error);
        }
    });

    /**
     * Listens for a notification about a reply to an email and updates the client keys.
     * Refreshes the lists of available and connection-received friends.
     */
    socket.on('email_reply_notify', function (data) {
        try {
            clientKeys[data['sender']].status = "con_reply_recv";
            saveClientKeys();
            loadAvailableFriends();
            loadConReceiveFriends();
        } catch (error) {
            console.error("Error handling email_reply_notify:", error);
        }
    });

    /**
     * Handles incoming chat messages. Ensures secure decryption, validates message order, 
     * and updates the chat display. Displays an error message if the order is incorrect.
     */
    socket.on('message', async (data) => {
        try {
            let ul = document.getElementById("chat-msg");
            
            // If the message is from a new sender, initialize a new chat session.
            if (chatClient != data["sender"]) {
                displaySelectFriendMessage(false);
                let li = document.createElement("li");
                li.appendChild(document.createTextNode(`Chat with - ${data["sender"]}`));
                li.classList.add("center_user");
                ul.appendChild(li);
                ul.scrollTop = ul.scrollHeight;

                chatClient = data["sender"];
                chatClientPK = clientKeys[data["sender"]].publicKey;
            }

            isCurrentUser = false;

            console.log("Sender------------", data["sender"]);
            console.log("Sender Encrypted Message------------", data["message"]);

            // Decrypt the received message using the private key and display it.
            const decryptedMessage = await decryptMessage(privateKey, data["message"]);
            console.log("Sender Decrypted Message------------", decryptedMessage);

            clientKeys[data["sender"]].receivedMessageId += 1;
            console.log("Received message id------------", clientKeys[data["sender"]].receivedMessageId);

            const hasColon = decryptedMessage.includes(':');

            // Processes the message if it's in the correct format (contains a colon to separate ID and content).
            if (hasColon) {
                const parts = decryptedMessage.split(/:(.+)/);
                const receivedMessageId = parts[0];
                const receivedMessage = parts[1];

                if (receivedMessageId == clientKeys[data["sender"]].receivedMessageId) {
                    let li = document.createElement("li");
                    li.appendChild(document.createTextNode(data["sender"] + " : " + receivedMessage));
                    li.classList.add("left-align");
                    ul.appendChild(li);
                    ul.scrollTop = ul.scrollHeight;
                } else {
                    const selectFriend = document.getElementById('select-friend');
                    const message = document.createElement('p');
                    message.style.color = 'red';
                    message.textContent = 'Message order not correct...!!!!';
                    selectFriend.appendChild(message);
                }
            } else {
                console.log('Message format error...');
            }
        } catch (error) {
            console.error("Error during decryption:", error);
        }
    });

    /**
     * Handles the retrieval of all users from the server and updates the client keys object.
     * Newly discovered users are added as available, excluding the current user.
     */
    socket.on("allUsers", function (data) {
        for (const [key, email] of Object.entries(data["allClients"])) {
            console.log("-------start-------");
            console.log('Client key ------ > ', key);
            console.log('Username ------ > ', username);
            
            // Adds new users to the clientKeys object while skipping the current user.
            if ((!(key in clientKeys)) && (key != username)) {
                console.log("All Users------>", key);
                clientKeys[key] = {
                    'username': key,
                    'publicKey': '',
                    'email': email,
                    'status': 'available',
                    'sendMessageId': 0,
                    'receivedMessageId': 0
                };
            }
            console.log("-end->>>>>>");
        }
        console.log('available <-> ', clientKeys);
        saveClientKeys();
        loadAvailableFriends();
    });
});

/**
 * Handles the logout event triggered by the server for specific users.
 * Updates the UI to indicate the user has logged out, removes their keys from local storage, 
 * and refreshes the lists of available, received, and accepted friends.
 */
socket.on('logoutUsers', function (data) {
    var clientKey = data['logoutUser'];
    console.log('User logout========>', clientKey);
    console.log('Client keys========>', clientKeys);

    // If the currently active chat user logs out, update the UI and reset the active chat client.
    if (chatClient == data['logoutUser']) {
        let ul = document.getElementById("chat-msg");
        let li = document.createElement("li");
        li.appendChild(document.createTextNode(`${data['logoutUser']} - User Logout`));
        li.classList.add("logout_user");
        ul.appendChild(li);
        ul.scrollTop = ul.scrollHeight;
        chatClient = null;
    }

    // Remove the logged-out user's keys and refresh the friend lists.
    if (clientKey in clientKeys) {
        delete clientKeys[clientKey];
        console.log('Client keys after delete========>', clientKeys);
        saveClientKeys();
        loadAvailableFriends();
        loadConReceiveFriends();
        loadAccepetdFriends();
    }
});

/**
 * Handles a server directive to redirect the user to the logout process.
 * Triggers the client-side logout function.
 */
socket.on('logout_redirect', function () {
    logout();
});

/**
 * Logs errors related to the logout process for debugging and monitoring purposes.
 */
socket.on('error', function (errorData) {
    console.log("Logout Error ------- ", errorData.message);
});

/**
 * Handles the send button click event. Sends the message to the active chat client 
 * if one is selected, otherwise displays a warning to select a friend first.
 */
document.getElementById('send').onclick = async () => {
    if (chatClient != null) {
        displaySelectFriendMessage(false);
        await sendMessage();
        socket.emit('stop_typing', { sender: username, recipient: chatClient });
    } else {
        displaySelectFriendMessage(true);
    }
};

/**
 * Handles the clear chat history button click event. Clears all chat messages from the UI.
 */
document.getElementById('clearHistory').onclick = async () => {
    let ul = document.getElementById("chat-msg");
    ul.innerHTML = "";
};

/**
 * Handles the keypress event in the message input box.
 * Sends the message on pressing Enter and emits typing events for other keys.
 */
document.getElementById("message-input").addEventListener("keypress", async function (event) {
    if (event.key === "Enter") {
        if (chatClient != null) {
            displaySelectFriendMessage(false);
            await sendMessage();
            socket.emit('stop_typing', { sender: username, recipient: chatClient });
        } else {
            displaySelectFriendMessage(true);
        }
    } else {
        console.log("Keypress detected, sending typing event");
        socket.emit('typing', { sender: username, recipient: chatClient });
    }
});

/**
 * Handles the keyup event in the message input box. Stops the typing indicator when Enter is pressed.
 */
document.getElementById("message-input").addEventListener("keyup", function (event) {
    if (event.key === "Enter") {
        console.log("Enter key pressed, sending stop typing event");
        socket.emit('stop_typing', { sender: username, recipient: chatClient });
    }
});

/**
 * Handles the blur event (input losing focus) in the message input box.
 * Stops the typing indicator when the input is no longer active.
 */
document.getElementById("message-input").addEventListener("blur", function () {
    console.log("Input lost focus, sending stop typing event");
    socket.emit('stop_typing', { sender: username, recipient: chatClient });
});

/**
 * Handles the logout button click event. Sends a logout event to the server and clears local storage data.
 */
document.getElementById('logout-btn').onclick = () => {
    socket.emit('logout', { user_name: username });
    localStorage.clear();
};

/**
 * Displays a typing indicator when a typing event is received from another user.
 */
socket.on('typing', function (data) {
    console.log("Received typing event from", data.sender);
    const typingIndicator = document.getElementById("typing-indicator");
    typingIndicator.textContent = data.sender + " is typing...";
});

/**
 * Removes the typing indicator when a stop typing event is received from another user.
 */
socket.on('stop_typing', function (data) {
    console.log("Received stop typing event from", data.sender);
    const typingIndicator = document.getElementById("typing-indicator");
    typingIndicator.textContent = "";
});

/**
 * Function to initialize the user by setting up their username, loading keys, and establishing a socket connection.
 * If a private key exists in localStorage, it is loaded. Otherwise, a new RSA key pair is generated.
 * The user's public key is also loaded, and a socket connection is initiated.
 */
async function initiateUser() {
    try {
        username = userData.Username;
        console.log("Initiating user with username:", username);

        // Check if private key exists in localStorage and load it if present.
        const privateKeyBase64 = localStorage.getItem('privateKey');
        if (privateKeyBase64) {
            await loadPrivateKey();
            console.log("Using existing private key.");
        } else {
            publicKey = await generateRSAKeyPair();
            console.log("Generated new RSA key pair.");
        }

        // Load public key from localStorage.
        loadPublicKey();

        // Establish socket connection and emit user join event with username and email.
        socket.connect();
        console.log("Socket connection established for username:", userData.Username);
        console.log("User email:", userData.Email);
        socket.on("connect", function () {
            socket.emit('user_join', { recipient: userData.Username, email: userData.Email });
        });
    } catch (error) {
        console.error("Error during user initialization:", error);
    }
}

/**
 * Function to load and display the list of available friends.
 * Displays different actions based on the user's status (e.g., available, invitation sent).
 */
function loadAvailableFriends() {
    var friendsList = document.getElementById("friends-list");
    friendsList.innerHTML = "";

    for (const [key, user] of Object.entries(clientKeys)) {
        console.log("Loading available friend:", user.username);
        console.log("Email:", user.email);
        console.log("Status:", user.status);

        let li = document.createElement("li");

        console.log("User status (available friends):", user.status);
        if (user.status === 'con_sent') {
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
                <div class="action"><input type="button" style="background-color:rgb(196, 128, 32);" value="Invitation Sent" disabled></div>
            `;
        } else if (user.status === 'available') {
            console.log("User public key:", publicKey);
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
                <div class="action"><input type="button" name="connect" value="Invite to chat" onclick='openEmailClientWindow(${JSON.stringify(user)}, "${publicKey}")'></div>
            `;
        }

        friendsList.appendChild(li);
    }
}

/**
 * Function to load and display the list of received connection requests.
 * Displays different actions based on the user's status and presence of a public key.
 */
function loadConReceiveFriends() {
    var friendsList = document.getElementById("received-list");
    friendsList.innerHTML = "";

    for (const [key, user] of Object.entries(clientKeys)) {
        console.log("Loading connection request from user:", user.username);
        console.log("Email:", user.email);
        console.log("Status:", user.status);

        let li = document.createElement("li");

        console.log("User status (received connections):", user.status);
        if ((user.status === 'con_recv' || user.status === 'con_reply_recv') && user.publicKey === "") {
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
                <div class="action"><input type="button" name="add_friend" value="Add ParsePhase" onclick='loadReply(${JSON.stringify(user)}, "${publicKey}")'></div>
            `;
        } else if (user.status === 'con_recv' && user.publicKey !== "") {
            console.log("Public key available for user:", publicKey);
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
                <div class="action"><input type="button" name="add_friend" value="Send Confirmation" style="background-color:rgb(196, 128, 32);" onclick='loadReply(${JSON.stringify(user)}, "${publicKey}")'></div>
            `;
        }

        friendsList.appendChild(li);
    }
}

/**
 * Handles the Add ParsePhase button click. Extracts and validates the public key
 * from the input, updates the client's keys, and reloads the received and accepted friends lists.
 * @param {*} friendObj - The object containing friend data.
 */
function OnAddParsePhaseClick(friendObj) {
    var parsePhase = document.getElementById("body_parsephase").value;
    console.log("Adding ParsePhase for user:", friendObj.username);
    console.log("ParsePhase value entered:", parsePhase);

    const hasColon = parsePhase.includes(':');
    if (hasColon) {
        const parts = parsePhase.split(/:(.+)/);
        const parsePhaseUser = parts[0];
        const parsePhasePublicKey = parts[1];

        if (parsePhaseUser === friendObj.username) {
            console.log("Public key validated for user:", parsePhaseUser);
            clientKeys[friendObj.username].publicKey = parsePhasePublicKey;
            document.getElementById('email_request_form').innerHTML = '';
            document.getElementById('email_reply_form').innerHTML = '';
            saveClientKeys();
            loadConReceiveFriends();
            loadAccepetdFriends();
        } else {
            console.error("Incorrect public key entered for user:", friendObj.username);
            publicKeyLoadForm(friendObj, true, 'Please Enter Correct Public Key');
        }
    } else {
        console.error("Public key format invalid. No colon detected.");
        publicKeyLoadForm(friendObj, true, 'Please Enter Correct Public Key');
    }
}

/**
 * Loads the chat list of accepted friends by iterating over the clientKeys.
 * Filters users with a status of 'accepted' and displays them in the connections list.
 * Clicking on a user switches the active chat client and appends a message in the chat.
 */
function loadAccepetdFriends() {
    var friendsList = document.getElementById("connections-list");
    friendsList.innerHTML = "";

    for (const [key, user] of Object.entries(clientKeys)) {
        console.log(`Loading user: ${user.username}, Email: ${user.email}, Status: ${user.status}`);

        let li = document.createElement("li");

        console.log(`Checking user status for: ${user.username}, Status: ${user.status}`);
        if (user.status === 'accepted') {
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
            `;

            li.addEventListener("click", () => {
                if (chatClient !== key) {
                    chatClient = key;
                    chatClientPK = user.publicKey;
                    displaySelectFriendMessage(false);

                    let ul = document.getElementById("chat-msg");
                    let li = document.createElement("li");
                    li.appendChild(document.createTextNode(`Chat with - ${chatClient}`));
                    li.classList.add("center_user");
                    ul.appendChild(li);
                    ul.scrollTop = ul.scrollHeight;

                    console.log(`Chat client switched to: ${chatClient}`);
                }
            });
        }

        friendsList.appendChild(li);
    }
}

/**
 * Handles sending connection requests and updates the clientKeys status accordingly.
 * Also triggers appropriate UI updates based on the status ('con_sent' or 'con_recv').
 */
function OnRequestSend(obj, status) {
    console.log(`Handling request send for user: ${obj.username}, Status: ${status}`);

    if (status === "con_sent") {
        clientKeys[obj.username].status = "con_sent";
        saveClientKeys();
        socket.emit('send_email_notification', { 
            recipient_name: obj.username, 
            notification: "Public Key Request Sent" 
        });
        loadAvailableFriends();
        console.log(`Connection request sent to: ${obj.username}`);
    } else if (status === "con_recv") {
        clientKeys[obj.username].status = "accepted";
        saveClientKeys();
        socket.emit('reply_email_notification', { 
            recipient_name: obj.username, 
            notification: "Public Key Reply Sent" 
        });
        loadConReceiveFriends();
        loadAccepetdFriends();
        console.log(`Connection accepted for: ${obj.username}`);
    }

    document.getElementById('email_request_form').innerHTML = '';
    document.getElementById('email_reply_form').innerHTML = '';
}

/**
 * Opens a new browser window for sending an email request with an invitation.
 * Pre-fills the form fields with the recipient's email, subject, and body.
 */
function openEmailClientWindow(obj, publicKey) {
    console.log(`Opening email client for: ${obj.username}, Status: ${obj.status}`);

    if (obj.status === 'available') {
        clientKeys[obj.username].status = "con_sent";
        saveClientKeys();
        socket.emit('send_email_notification', { 
            recipient_name: obj.username, 
            notification: "Public Key Request Sent" 
        });
        loadAvailableFriends();
    }

    const emailWindow = window.open('', '_blank', 'width=600,height=400');
    const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Send Gobuzz Chat Invitation</title>
            <style>
                /* Add your CSS styles for the email client window here */
            </style>
        </head>
        <body>
            <div class="email-form-container">
                <form id="emailForm">
                    <label for="email">To:</label>
                    <input type="email" id="email" name="email" value="${obj.email}" required>
                    <label for="subject">Subject:</label>
                    <input type="text" id="subject" name="subject" value="GoBuzz Chat Invitation" required>
                    <label for="body">Body:</label>
                    <textarea id="body" name="body" required>${publicKey}</textarea>  
                    <button type="submit">Send Request</button>
                </form>
            </div>
        </body>
        </html>
    `;

    emailWindow.document.write(htmlContent);
    emailWindow.document.close();

    const scriptContent = `
        document.getElementById('emailForm').addEventListener('submit', function(event) {
            event.preventDefault();
            const email = document.getElementById('email').value;
            const subject = document.getElementById('subject').value;
            const body = document.getElementById('body').value;

            if (email && subject && body) {
                const mailtoLink = 'mailto:' + email + '?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);
                window.open(mailtoLink, '_blank');
                window.close();
            } else {
                alert('All fields are required.');
            }
        });
    `;

    const script = emailWindow.document.createElement('script');
    script.textContent = scriptContent;
    emailWindow.document.body.appendChild(script);
    console.log(`Email client window prepared for: ${obj.email}`);
}

