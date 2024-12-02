const socket = io({ autoConnect: false });
let privateKey, publicKey;
var clientKeys = JSON.parse(localStorage.getItem('clientKeys')) || {};
var username, chatClient, chatClientPK;
var isCurrentUser = true;

// Function to save clientKeys to localStorage
function saveClientKeys() {
    localStorage.setItem('clientKeys', JSON.stringify(clientKeys));
}

// Function to save publicKey to localStorage
function savePublicKey() {
    localStorage.setItem('publicKey', publicKey);
}

// Function to load publicKey from localStorage
function loadPublicKey() {
    publicKey = localStorage.getItem('publicKey');
}

// Function to save privateKey to localStorage
async function savePrivateKey() {
    const exportedPrivateKey = await window.crypto.subtle.exportKey("pkcs8", privateKey);
    const privateKeyBase64 = arrayBufferToBase64(exportedPrivateKey);
    const encryptedPrivateKey = await encryptPrivateKey(privateKeyBase64, 'your-password'); // Encrypt with a password
    localStorage.setItem('privateKey', encryptedPrivateKey);
}

// Function to load privateKey from localStorage
async function loadPrivateKey() {
    const encryptedPrivateKey = localStorage.getItem('privateKey');
    if (encryptedPrivateKey) {
        const privateKeyBase64 = await decryptPrivateKey(encryptedPrivateKey, 'your-password'); // Decrypt with a password
        const privateKeyArrayBuffer = base64ToArrayBuffer(privateKeyBase64);
        privateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            privateKeyArrayBuffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["decrypt"]
        );
        console.log("Private key successfully loaded.");
    } else {
        console.log("No private key found in localStorage.");
    }
}

// Function to encrypt the private key
async function encryptPrivateKey(privateKeyBase64, password) {
    const passwordKey = await getPasswordKey(password);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        passwordKey,
        new TextEncoder().encode(privateKeyBase64)
    );
    const encryptedContentArr = new Uint8Array(encryptedContent);
    const buff = new Uint8Array(iv.byteLength + encryptedContentArr.byteLength);
    buff.set(iv, 0);
    buff.set(encryptedContentArr, iv.byteLength);
    return arrayBufferToBase64(buff);
}

// Function to decrypt the private key
async function decryptPrivateKey(encryptedPrivateKeyBase64, password) {
    const encryptedPrivateKeyBuff = base64ToArrayBuffer(encryptedPrivateKeyBase64);
    const iv = encryptedPrivateKeyBuff.slice(0, 12);
    const data = encryptedPrivateKeyBuff.slice(12);
    const passwordKey = await getPasswordKey(password);
    const decryptedContent = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        passwordKey,
        data
    );
    return new TextDecoder().decode(decryptedContent);
}

// Function to get a key from a password
async function getPasswordKey(password) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode("salt"), 
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// Function to handle form events
document.addEventListener('DOMContentLoaded', function () {
    console.log("Page loaded. Initializing form event handlers...");

    // Select all forms
    const forms = document.querySelectorAll('form');

    // Add event listener to each form
    forms.forEach(form => {
        form.addEventListener('submit', function (event) {
            // Prevent default form submission, this is from the original form
            event.preventDefault();

            // Serialize form data
            const formData = new FormData(form);
            const email = formData.get('email');
            const subject = encodeURIComponent(formData.get('subject'));
            const body = encodeURIComponent(formData.get('body'));

            // Create mailto link
            const mailtoLink = `mailto:${email}?subject=${subject}&body=${body}`;

            // Open mailto link
            window.location.href = mailtoLink;

            // Reset the form values after submission
            form.reset();
        });
    });
});

document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById("logout-btn").value = "Logout-" + userData.Username;

    // Load privateKey and publicKey from localStorage
    await loadPrivateKey();
    loadPublicKey();

    // Re-establish connection using data from localStorage
    if (Object.keys(clientKeys).length > 0) {
        loadAvailableFriends();
        loadConReceiveFriends();
        loadAccepetdFriends();
    }

    socket.on('email_send_notify', function (data) {
        try {
            clientKeys[data['sender']].status = "con_recv"
            saveClientKeys();
            loadConReceiveFriends();
            loadAvailableFriends();
        } catch (error) {
            console.error("Error message error:", error);
        }
    })


    socket.on('email_reply_notify', function (data) {
        try {
            clientKeys[data['sender']].status = "con_reply_recv";
            saveClientKeys();
            loadAvailableFriends();
            loadConReceiveFriends();
        } catch (error) {
            console.error("Error message error:", error);
        }
    })

    socket.on('message', async (data) => {
        try {
            let ul = document.getElementById("chat-msg");
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
            console.group('Message Processing');
            console.log('From:', data["sender"]);
    
            const decryptedMessage = await decryptMessage(privateKey, data["message"]);
            const [messageId, message] = decryptedMessage.split(/:(.+)/);
            
            // Validate message order
            const expectedId = (clientKeys[data["sender"]].receivedMessageId || 0) + 1;
            if (parseInt(messageId) !== expectedId) {
                console.error(`Message order incorrect. Expected: ${expectedId}, Got: ${messageId}`);
                const selectFriend = document.getElementById('select-friend');
                const errorMsg = document.createElement('p');
                errorMsg.style.color = 'red';
                errorMsg.textContent = `Message order incorrect (${messageId}/${expectedId}). Synchronization issue detected.`;
                selectFriend.appendChild(errorMsg);
                return;
            }
    
            // Update message counter and display message
            clientKeys[data["sender"]].receivedMessageId = expectedId;
            let li = document.createElement("li");
            li.appendChild(document.createTextNode(`${data["sender"]} : ${message}`));
            li.classList.add("left-align");
            ul.appendChild(li);
            ul.scrollTop = ul.scrollHeight;
            
            console.groupEnd();
            saveClientKeys(); // Save updated message counter
        } catch (error) {
            console.error("Error processing message:", error);
        }
    });

    socket.on("allUsers", function (data) {
        //console.log('All clients----->',data['allClients'])
        for (const [key, email] of Object.entries(data["allClients"])) {
            console.log("-------start-------");
            console.log('Client key ------ > ', key)
            console.log('Username ------ > ', username)
            if ((!(key in clientKeys)) && (key != username)) {
                console.log("All Users------>", key);
                clientKeys[key] = {
                    'username': key,
                    'publicKey': '',
                    'email': email,
                    'status': 'available',
                    'sendMessageId': 0,
                    'receivedMessageId': 0
                }
            }
            console.log("-------end-------");
        }
        console.log('All users available ------ > ', clientKeys)
        saveClientKeys();
        loadAvailableFriends();
    });

    socket.on('logoutUsers', function (data) {
        var clientKey = data['logoutUser']
        console.log('User logout========>', clientKey)
        console.log('Client keys========>', clientKeys)
        if (chatClient == data['logoutUser']) {
            let ul = document.getElementById("chat-msg");
            let li = document.createElement("li");
            li.appendChild(document.createTextNode(`${data['logoutUser']} - User Logout`));
            li.classList.add("logout_user");
            ul.appendChild(li);
            ul.scrollTop = ul.scrollHeight;

            chatClient = null;
        }
        if (clientKey in clientKeys) {
            delete clientKeys[clientKey];
            console.log('Client keys after delete========>', clientKeys)
            saveClientKeys();
            loadAvailableFriends();
            loadConReceiveFriends();
            loadAccepetdFriends();
        }
    });

    socket.on('logout_redirect', function () {
        logout()
    });

    socket.on('error', function (errorData) {
        console.log("Logout Error ------- ", errorData.message)
    });

    document.getElementById('send').onclick = async () => {
        if (chatClient != null){
            displaySelectFriendMessage(false);
            await sendMessage();
            socket.emit('stop_typing', { sender: username, recipient: chatClient });
        } else {
            displaySelectFriendMessage(true);
        }
        
    };

    document.getElementById('clearHistory').onclick = async () => {
        let ul = document.getElementById("chat-msg");
        ul.innerHTML = ""
    };

    document.getElementById("message-input").addEventListener("keypress", async function (event) {
        if (event.key === "Enter") {
            if (chatClient != null){
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

    document.getElementById("message-input").addEventListener("keyup", function (event) {
        if (event.key === "Enter") {
            console.log("Enter key pressed, sending stop typing event");
            socket.emit('stop_typing', { sender: username, recipient: chatClient });
        }
    });

    document.getElementById("message-input").addEventListener("blur", function () {
        console.log("Input lost focus, sending stop typing event");
        socket.emit('stop_typing', { sender: username, recipient: chatClient });
    });

    document.getElementById('logout-btn').onclick = () => {
        socket.emit('logout', { user_name: username });
        localStorage.clear(); // Clear all local storage data
    };

    socket.on('typing', function (data) {
        console.log("Received typing event from", data.sender);
        const typingIndicator = document.getElementById("typing-indicator");
        typingIndicator.textContent = data.sender + " is typing...";
    });

    socket.on('stop_typing', function (data) {
        console.log("Received stop typing event from", data.sender);
        const typingIndicator = document.getElementById("typing-indicator");
        typingIndicator.textContent = "";
    });
});


async function initiateUser() {
    try {
        username = userData.Username;
        console.log("Initiate user===============================>>", username)

        // Check if private key exists in localStorage
        const privateKeyBase64 = localStorage.getItem('privateKey');
        if (privateKeyBase64) {
            await loadPrivateKey();
            console.log("Using existing private key.");
        } else {
            publicKey = await generateRSAKeyPair();
            console.log("Generated new key pair.");
        }

        // Load publicKey from localStorage
        loadPublicKey();

        socket.connect();
        console.log('Username------->', userData.Username)
        console.log('Email------->', userData.Email)
        socket.on("connect", function () {
            // socket.emit('user_join', { recipient: userData.Username, publicKey: clientPublicKey });
            socket.emit('user_join', { recipient: userData.Username, email: userData.Email });
        });


        // document.getElementById("chat_header_text").textContent = `CryptoGram [${userData.Username}]`;

    } catch (error) {
        console.error("Error initiating user:", error);
    }
}

/**
 * Function to load the chat list
 */
function loadAvailableFriends() {
    var friendsList = document.getElementById("friends-list");
    friendsList.innerHTML = "";

    for (const [key, user] of Object.entries(clientKeys)) {
        console.log("user==" + user['username']);
        console.log("user==" + user['email']);
        console.log("user==" + user['status']);

        let li = document.createElement("li");

        console.log("user['status'] available=====" + user['status']);

        if (user['status'] == 'con_sent') {
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
                <div class="action"><input type="button" style="background-color:rgb(196, 128, 32);" value="Invitation Sent" disabled></div>
            `;
        } else if (user['status'] == 'available') {            
            console.log("Public key---------------> "+publicKey);
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
 * Function to load the chat list
 */
function loadConReceiveFriends() {
    var friendsList = document.getElementById("received-list");
    friendsList.innerHTML = "";

    for (const [key, user] of Object.entries(clientKeys)) {
        console.log("user==" + user['username']);
        console.log("user==" + user['email']);
        console.log("user==" + user['status']);

        let li = document.createElement("li");

        console.log("user['status'] loadConReceiveFriends=====" + user['status']);
        if ((user['status'] == 'con_recv' || user['status'] == 'con_reply_recv') && user['publicKey'] == "") {
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
                <div class="action"><input type="button" name="add_friend" value="Add Chat Secret" onclick='loadReply(${JSON.stringify(user)}, "${publicKey}")'></div>
            `;
        } else if (user['status'] == 'con_recv' && user['publicKey'] != "") {
            console.log("con_recv:Public key---------------> "+publicKey);
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
 * onclick method for button click 
 * @param {*} friendObj 
 */
function OnAddParsePhaseClick(friendObj) {
    //console.log("OnAddParsePhaseClick----:");
    var parsePhase = document.getElementById("body_parsephase").value;
    console.log("OnAddParsePhaseClick-parsePhase=", parsePhase);

    const hasColon = parsePhase.includes(':');

    if (hasColon) {
        const parts = parsePhase.split(/:(.+)/);

        const parsePhaseUser = parts[0];
        const parsePhasePublicKey = parts[1];

        if (parsePhaseUser == friendObj.username) {
            clientKeys[friendObj.username].publicKey = parsePhasePublicKey;
            document.getElementById('email_request_form').innerHTML = '';
            document.getElementById('email_reply_form').innerHTML = '';
            saveClientKeys();
            loadConReceiveFriends();
            loadAccepetdFriends();
        } else {
            publicKeyLoadForm(friendObj, true, 'Please Enter Correct Public Key')
        }
    } else {
        publicKeyLoadForm(friendObj, true, 'Please Enter Correct Public Key')
    }
}


/**
 * Function to load the chat list
 */
function loadAccepetdFriends() {
    var friendsList = document.getElementById("connections-list");
    friendsList.innerHTML = "";

    for (const [key, user] of Object.entries(clientKeys)) {
        console.log("user==" + user['username']);
        console.log("user==" + user['email']);
        console.log("user==" + user['status']);

        let li = document.createElement("li");

        console.log("user['status'] loadAccepetdFriends=====" + user['status']);
        if (user['status'] == 'accepted') {
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
            `;

            li.addEventListener("click", () => {
                if (chatClient != key){
                    chatClient = key;
                    chatClientPK = user.publicKey
                    displaySelectFriendMessage(false)

                    
                    let ul = document.getElementById("chat-msg");
                    let li = document.createElement("li");
                    li.appendChild(document.createTextNode(`Chat with - ${chatClient}`));
                    li.classList.add("center_user");
                    ul.appendChild(li);
                    ul.scrollTop = ul.scrollHeight;
                }
            });
        }

        friendsList.appendChild(li);
    }
}

/**
 * Button click function for sending connection request via an email
 * this will open the email client for sending the email.
 */
function OnRequestSend(obj, status) {

    console.log('Status OnRequestSend------->', status)
    if (status == "con_sent") {
        clientKeys[obj.username].status = "con_sent";
        saveClientKeys();
        socket.emit('send_email_notification', { recipient_name: obj.username, notification: "Public Key Request Send" });
        loadAvailableFriends();
    } else if (status == "con_recv") {
        clientKeys[obj.username].status = "accepted"
        saveClientKeys();
        socket.emit('reply_email_notification', { recipient_name: obj.username, notification: "Public Key Reply Send" });
        loadConReceiveFriends();
        loadAccepetdFriends();
    }

    document.getElementById('email_request_form').innerHTML = '';
    document.getElementById('email_reply_form').innerHTML = '';
}

/**
 * Function to open the email sending window.
 */
function openEmailClientWindow(obj, publicKey) {    

    if(obj.status == 'available')
    {
        // execute pre-processing
        clientKeys[obj.username].status = "con_sent";
        saveClientKeys();
        socket.emit('send_email_notification', { recipient_name: obj.username, notification: "Public Key Request Send" });
        loadAvailableFriends();
    }
    
    const emailWindow = window.open('', '_blank', 'width=600,height=400');    
    // Define the HTML content for the new window to send the email request with invitation
    const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Send Gobuzz Chat Invitation</title>
            <style>
                body {
                font-family: Arial, sans-serif;
                justify-content: center;
                align-items: center;
                height: 100vh;
                background: linear-gradient(135deg, #72EDF2 10%, #5151E5 100%);
                margin: 0;

                .email-form-container {
                    max-width: 500px;
                    margin: 20px auto;
                    padding: 20px;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                    background-color: #f9f9f9;
                }

                .email-form-container h1 {
                    text-align: center;
                    margin-bottom: 20px;
                    color: #333;
                }

                .email-form-container form {
                    display: flex;
                    flex-direction: column;
                }

                .email-form-container label {
                    margin-bottom: 5px;
                    font-weight: normal;
                    color: #555;
                    font-size: 15px;
                }

                .email-form-container input[type="email"],
                .email-form-container input[type="text"],
                .email-form-container textarea {
                    width: 100%;
                    padding: 5px 5px 5px 5px;
                    margin-bottom: 1px;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    font-size: 16px;
                    color: #333;
                }

                .email-form-container input[type="email"]:focus,
                .email-form-container input[type="text"]:focus,
                .email-form-container textarea:focus {
                    border-color: #007bff;
                    outline: none;
                }

                .email-form-container textarea {
                    height: 100px;
                    resize: vertical;
                }

                .email-form-container button {
                    margin-top: 5px;
                    padding: 10px 15px;
                    font-size: 16px;
                    color: #fff;
                    background-color: #007bff;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    transition: background-color 0.3s ease;
                }

                .email-form-container button:hover {
                    background-color: #0056b3;
                }
            }
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

    // Inject the script to handle form submission after the HTML is written
    const scriptContent = `
        document.getElementById('emailForm').addEventListener('submit', function(event) {
            event.preventDefault(); // Prevent the form from submitting the traditional way
            const email = document.getElementById('email').value;
            const subject = document.getElementById('subject').value;
            const body = document.getElementById('body').value;

            if (email && subject && body) {
                const mailtoLink = 'mailto:' + email + '?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);
                //window.opener.notifyEmailSent(email);
                window.open(mailtoLink, '_blank'); // Open the email client
                window.close(); // Close the email client window
            } else {
                alert('All fields are required.');
            }
        });
    `;
    
    const script = emailWindow.document.createElement('script');
    script.textContent = scriptContent;
    emailWindow.document.body.appendChild(script);
}

/**
 * Function to load the email request
 */
function loadRequest(obj, publicKey) {
    const formContent = `
        <div class="email-form-container">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" value="${obj.email}" required>            
            <label for="subject">Subject:</label>
            <input type="text" id="subject" name="subject" value="GOBUZZ Public Key For - ${obj.username}" required>            
            <label for="body">Body:</label>
            <textarea id="body" name="body" required>${publicKey}</textarea>            
            <button type="button" onclick='OnRequestSend(${JSON.stringify(obj)}, "con_sent")'>Request To Connect</button>
        </div>
    `;
    document.getElementById('email_request_form').innerHTML = formContent;
}

/**
 * Function to load the email request
 */
function loadReply(obj, publicKey) {
    let formContent;

    if (clientKeys[obj.username].status == "con_recv" && clientKeys[obj.username].publicKey != "") {
        clientKeys[obj.username].status = "accepted"
        saveClientKeys();
        socket.emit('reply_email_notification', { recipient_name: obj.username, notification: "Public Key Reply Send" });
        loadConReceiveFriends();
        loadAccepetdFriends();
        openEmailClientWindow(obj, publicKey);
    } else {
        publicKeyLoadForm(obj, false, 'nil');
    }
}


async function sendMessage() {
    try {
        if (!chatClientPK) {
            console.error('No public key available for recipient');
            return;
        }

        clientKeys[chatClient].sendMessageId = (clientKeys[chatClient].sendMessageId || 0) + 1;
        const messageId = clientKeys[chatClient].sendMessageId;
        
        const clientMessageText = document.getElementById('message-input').value;
        if (!clientMessageText.trim()) {
            console.error('Empty message cannot be sent');
            return;
        }

        const clientMessage = `${messageId}:${clientMessageText}`;
        console.group('Message Encryption');
        console.log('Message ID:', messageId);
        console.log('Original message:', clientMessageText);
        
        const encryptedMessage = await encryptMessage(chatClientPK, clientMessage);
        
        socket.emit('message', { 
            recipient_name: chatClient, 
            message: encryptedMessage 
        });

        // Update UI
        let ul = document.getElementById("chat-msg");
        let li = document.createElement("li");
        li.appendChild(document.createTextNode("Me : " + clientMessageText));
        li.classList.add("right-align");
        ul.appendChild(li);
        ul.scrollTop = ul.scrollHeight;

        // Clear input
        document.getElementById("message-input").value = "";
        console.groupEnd();
    } catch (error) {
        console.error('Error sending message:', error);
    }
}

async function generateRSAKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );

    const publicKeyArrayBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyBase64 = username + ':' + arrayBufferToBase64(publicKeyArrayBuffer);


    console.log("Generated Public Key (Base64):", publicKeyBase64);
    privateKey = keyPair.privateKey;

    // Save the private key to localStorage
    await savePrivateKey();

    // Save the public key to localStorage
    publicKey = publicKeyBase64;
    savePublicKey();

    return publicKeyBase64;
}

async function generateSHA256Hash(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

async function encryptMessage(publicKeyBase64, message) {
    try {
        if (typeof publicKeyBase64 !== 'string' || !isBase64(publicKeyBase64)) {
            throw new Error("Public key is not a valid Base64 string.");
        }

        const publicKeyArrayBuffer = base64ToArrayBuffer(publicKeyBase64);

        const publicKey = await window.crypto.subtle.importKey(
            "spki",
            publicKeyArrayBuffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["encrypt"]
        );

        const encodedMessage = new TextEncoder().encode(message);

        const encryptedMessage = await window.crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            publicKey,
            encodedMessage
        );

        return arrayBufferToBase64(encryptedMessage);
    } catch (error) {
        console.error("Error during encryption:", error.message);
        throw error;
    }
}


async function decryptMessage(privateKey, encryptedMessage) {
    try {
        const decryptedMessage = await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            privateKey,
            base64ToArrayBuffer(encryptedMessage)
        );
        return new TextDecoder().decode(decryptedMessage);
    } catch (error) {
        console.error("Error during decryption:", error.message);
        throw error;
    }
}

function base64ToArrayBuffer(base64) {
    try {
        if (!isBase64(base64)) {
            throw new Error("Invalid Base64 string.");
        }

        const binaryString = window.atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (error) {
        console.error("Failed to convert Base64 to ArrayBuffer:", error.message);
        throw error;
    }
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function isBase64(str) {
    const base64Pattern = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/;
    return base64Pattern.test(str);
}

function displaySelectFriendMessage(visibility) {

    const selectFriend = document.getElementById('select-friend');
    if (visibility) {
        if (!selectFriend.querySelector('p')) { // Check if the message is not already displayed
            const message = document.createElement('p');
            message.style.color = 'red';
            message.textContent = 'Please select a friend to chat';
            selectFriend.appendChild(message);
        }
    } else {
        const message = selectFriend.querySelector('p');
        if (message) {
            selectFriend.removeChild(message);
        }
    }
    
}

function confirmLogout() {

    const modal = document.getElementById("confirmationModal");
    modal.style.display = "block";

    const confirmYes = document.getElementById("confirmYes");
    const confirmNo = document.getElementById("confirmNo");

    confirmYes.onclick = null;
    confirmNo.onclick = null;

    confirmYes.addEventListener('click', function () {
        socket.emit('logout', { user_name: username });
    });

    confirmNo.addEventListener('click', function () {
        modal.style.display = "none";
    });

    const closeBtn = document.getElementsByClassName("close")[0];
    closeBtn.onclick = function () {
        modal.style.display = "none";
    };

    window.onclick = function (event) {
        if (event.target === modal) {
            modal.style.display = "none";
        }
    };


}

function logout() {
    fetch('/logout', {
        method: 'GET',
        credentials: 'same-origin'
    }).then(response => {
        if (response.ok) {
            localStorage.clear(); // Clear all local storage data
            window.location.href = '/';
        } else {
            console.error("Logout failed");
        }
    }).catch(error => {
        console.error("Logout error:", error);
    });
}

/*
 * Key Exchange UI Management
 * Handles the display and interaction for secure key exchange
 */
function showKeyExchangeModal(user, isInitiator = true) {
    const modalHTML = `
        <div class="modal-overlay">
            <div class="key-exchange-modal">
                <div class="key-exchange-header">
                    <h2>${isInitiator ? 'Send Connection Request' : 'Accept Connection Request'}</h2>
                    <p>${isInitiator ? 
                        `Share your public key with ${user.username}` : 
                        `Share your public key with ${user.username} and verify their key`}</p>
                </div>
                
                ${isInitiator ? `
                    <div class="key-field-container">
                        <textarea class="key-input" readonly>${publicKey}</textarea>
                        <div class="key-actions">
                            <button class="key-btn copy-btn" onclick="copyKey()">
                                <span>📋</span> Copy Key
                            </button>
                            <button class="key-btn send-btn" onclick="sendKeyByEmail('${user.email}')">
                                <span>📤</span> Send via Email
                            </button>
                        </div>
                        <div class="success-message" id="success-message"></div>
                    </div>
                ` : `
                    <div class="key-field-container">
                        <textarea class="key-input" placeholder="Paste the received public key here" id="received-key"></textarea>
                        <div class="key-actions">
                            <button class="key-btn copy-btn" onclick="copyKey()">
                                <span>📋</span> Copy My Key
                            </button>
                            <button class="key-btn send-btn" onclick="verifyAndSendKey('${user.email}')">
                                <span>✅</span> Verify & Send
                            </button>
                        </div>
                        <div class="success-message" id="success-message"></div>
                    </div>
                `}
            </div>
        </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHTML);
}

async function copyKey() {
    try {
        await navigator.clipboard.writeText(publicKey);
        const successMessage = document.getElementById('success-message');
        successMessage.textContent = 'Key copied to clipboard!';
        successMessage.classList.add('show');
        setTimeout(() => successMessage.classList.remove('show'), 3000);
    } catch (err) {
        console.error('Failed to copy key:', err);
    }
}

async function sendKeyByEmail(recipientEmail) {
    try {
        const emailData = {
            to: recipientEmail,
            subject: 'Cryptogram Connection Request',
            body: `Your connection key is: ${publicKey}\n\nPlease use this key to establish a secure connection in Cryptogram.`
        };

        const response = await fetch('/api/send-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(emailData)
        });

        if (response.ok) {
            const successMessage = document.getElementById('success-message');
            successMessage.textContent = 'Key sent successfully!';
            successMessage.classList.add('show');
            
            // Update UI state
            clientKeys[recipientEmail].status = "con_sent";
            saveClientKeys();
            loadAvailableFriends();
            
            // Close modal after delay
            setTimeout(() => {
                document.querySelector('.modal-overlay').remove();
            }, 2000);
        } else {
            throw new Error('Failed to send email');
        }
    } catch (error) {
        console.error('Email sending failed:', error);
    }
}

async function verifyAndSendKey(senderEmail) {
    const receivedKey = document.getElementById('received-key').value;
    
    if (!receivedKey) {
        const successMessage = document.getElementById('success-message');
        successMessage.textContent = 'Please paste the received key first';
        successMessage.classList.add('show');
        return;
    }

    try {
        // Verify the received key
        if (verifyKey(receivedKey)) {
            await sendKeyByEmail(senderEmail);
            clientKeys[senderEmail].publicKey = receivedKey;
            clientKeys[senderEmail].status = "accepted";
            saveClientKeys();
            loadAccepetdFriends();
        } else {
            throw new Error('Invalid key format');
        }
    } catch (error) {
        console.error('Key verification failed:', error);
    }
}

function openEmailClientWindow(obj, publicKey) {    
    if(obj.status == 'available') {
        // Instead of opening email window, show key exchange UI
        showKeyExchangeModal(obj);
        clientKeys[obj.username].status = "con_sent";
        saveClientKeys();
        socket.emit('send_email_notification', { 
            recipient_name: obj.username, 
            notification: "Public Key Request Send" 
        });
        loadAvailableFriends();
    }
}

function showKeyExchangeModal(user) {
    const formContent = `
        <div class="parse-phase-container">
            <div class="parse-phase-header">
                <h3>Share Your Key</h3>
                <p>Send your public key to ${user.username}</p>
            </div>
            <div class="parse-phase-field">
                <textarea class="parse-phase-input" id="key-content" readonly>${publicKey}</textarea>
                <div class="parse-phase-actions">
                    <button onclick="copyKeyToClipboard()" class="parse-phase-button">
                        <span class="btn-icon">📋</span> Copy Key
                    </button>
                    <button onclick="sendKeyByEmail('${user.email}')" class="parse-phase-button">
                        <span class="btn-icon">📧</span> Send via Email
                    </button>
                </div>
            </div>
        </div>
    `;
    document.getElementById('email_request_form').innerHTML = formContent;
}

function publicKeyLoadForm(obj, showMsg, msg = '') {
    const formContent = `
        <div class="parse-phase-container">
            <div class="parse-phase-header">
                <h3>Enter Received Key</h3>
                <p>Paste the public key received from ${obj.username}</p>
            </div>
            <div class="parse-phase-field">
                <textarea 
                    id="body_parsephase" 
                    class="parse-phase-input" 
                    placeholder="Paste the received key here"
                ></textarea>
                ${showMsg ? `<div class="parse-phase-error show">${msg}</div>` : ''}
                <button 
                    onclick='OnAddParsePhaseClick(${JSON.stringify(obj)})' 
                    class="parse-phase-button"
                >
                    <span class="btn-icon">✅</span> Add ParsePhase
                </button>
            </div>
        </div>
    `;

    if (clientKeys[obj.username].status == "con_reply_recv") {
        clientKeys[obj.username].status = "accepted";
        saveClientKeys();
    }
    document.getElementById('email_reply_form').innerHTML = formContent;
}

async function copyKeyToClipboard() {
    const keyContent = document.getElementById('key-content');
    try {
        await navigator.clipboard.writeText(keyContent.value);
        showNotification('Key copied to clipboard!');
    } catch (err) {
        showNotification('Failed to copy key', 'error');
    }
}

async function sendKeyByEmail(recipientEmail) {
    try {
        const response = await fetch('/send-key-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email: recipientEmail,
                key: publicKey
            })
        });

        if (response.ok) {
            showNotification('Key sent via email!');
        } else {
            throw new Error('Failed to send email');
        }
    } catch (error) {
        showNotification('Failed to send email', 'error');
    }
}

function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

function loadReply(obj, publicKey) {
    let formContent;

    if (clientKeys[obj.username].status == "con_recv" && clientKeys[obj.username].publicKey != "") {
        // Show key exchange UI instead of opening email window
        showKeyExchangeUI(obj, publicKey, true);
        clientKeys[obj.username].status = "accepted";
        saveClientKeys();
        socket.emit('reply_email_notification', { 
            recipient_name: obj.username, 
            notification: "Public Key Reply Send" 
        });
        loadConReceiveFriends();
        loadAccepetdFriends();
    } else {
        publicKeyLoadForm(obj, false, 'nil');
    }
}

function showKeyExchangeUI(obj, publicKey, isConfirmation = false) {
    const formContent = `
        <div class="parse-phase-container">
            <div class="parse-phase-header">
                <h3>${isConfirmation ? 'Send Confirmation Key' : 'Share Your Key'}</h3>
                <p>${isConfirmation ? 
                    `Send your public key to confirm connection with ${obj.username}` : 
                    `Share your public key with ${obj.username}`}</p>
            </div>
            
            <div class="parse-phase-field">
                <label for="key-display">Your Public Key:</label>
                <textarea 
                    id="key-display" 
                    class="parse-phase-input" 
                    readonly
                >${publicKey}</textarea>
                
                <div class="parse-phase-actions">
                    <button onclick="copyKeyToClipboard('key-display')" class="parse-phase-button">
                        <span>📋</span> Copy Key
                    </button>
                    <button onclick="sendKeyByEmail('${obj.email}', '${publicKey}')" class="parse-phase-button">
                        <span>📧</span> Send via Email
                    </button>
                </div>
                
                <div id="key-action-message" class="parse-phase-message"></div>
            </div>
        </div>
    `;

    const targetElement = isConfirmation ? 
        document.getElementById('email_reply_form') : 
        document.getElementById('email_request_form');
    targetElement.innerHTML = formContent;
}

async function copyKeyToClipboard(elementId) {
    try {
        const keyContent = document.getElementById(elementId).value;
        await navigator.clipboard.writeText(keyContent);
        showActionMessage('Key copied to clipboard!', 'success');
    } catch (err) {
        showActionMessage('Failed to copy key', 'error');
        console.error('Copy failed:', err);
    }
}

async function sendKeyByEmail(recipientEmail, key) {
    try {
        const response = await fetch('/send-key-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                to: recipientEmail,
                subject: 'Cryptogram Connection Key',
                key: key
            })
        });

        if (response.ok) {
            showActionMessage('Key sent via email!', 'success');
        } else {
            throw new Error('Failed to send email');
        }
    } catch (error) {
        showActionMessage('Failed to send email', 'error');
        console.error('Email error:', error);
    }
}

function showActionMessage(message, type = 'success') {
    const messageElement = document.getElementById('key-action-message');
    if (messageElement) {
        messageElement.textContent = message;
        messageElement.className = `parse-phase-message ${type}`;
        setTimeout(() => {
            messageElement.textContent = '';
        }, 3000);
    }
}

function verifyKey(key) {
    // Check if key has the correct format (username:base64key)
    const hasColon = key.includes(':');
    if (!hasColon) return false;

    const [keyUsername, keyData] = key.split(/:(.+)/);
    // Verify the key belongs to the correct user
    if (!keyUsername) return false;
    
    // Verify the key is valid base64
    return isBase64(keyData);
}
