/*
 * Socket Connection and Key Management
 * Initializes WebSocket connection and handles cryptographic key management.
 * Uses WebCrypto API for RSA encryption/decryption operations.
 */
const socket = io({ autoConnect: false });
let privateKey, publicKey;
var clientKeys = JSON.parse(localStorage.getItem('clientKeys')) || {};
var username, chatClient, chatClientPK;
var isCurrentUser = true;

/*
 * Local Storage Management Functions
 * Handles saving and loading of keys and client information
 * to maintain persistence across sessions.
 */
function saveClientKeys() {
    localStorage.setItem('clientKeys', JSON.stringify(clientKeys));
}

function savePublicKey() {
    localStorage.setItem('publicKey', publicKey);
}

function loadPublicKey() {
    publicKey = localStorage.getItem('publicKey');
}

/*
 * Private Key Management
 * Handles encryption, storage, and retrieval of private keys
 * using password-based encryption for additional security.
 */
async function savePrivateKey() {
    const exportedPrivateKey = await window.crypto.subtle.exportKey("pkcs8", privateKey);
    const privateKeyBase64 = arrayBufferToBase64(exportedPrivateKey);
    const encryptedPrivateKey = await encryptPrivateKey(privateKeyBase64, 'your-password');
    localStorage.setItem('privateKey', encryptedPrivateKey);
}

async function loadPrivateKey() {
    const encryptedPrivateKey = localStorage.getItem('privateKey');
    if (encryptedPrivateKey) {
        const privateKeyBase64 = await decryptPrivateKey(encryptedPrivateKey, 'your-password');
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
        console.group('Private Key Management');
        console.log('Private key successfully loaded from storage');
        console.groupEnd();
    } else {
        console.group('Private Key Management');
        console.log('No private key found in storage');
        console.groupEnd();
    }
}

/*
 * Private Key Encryption/Decryption
 * Uses AES-GCM for secure storage of private keys
 * with password-based key derivation.
 */
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

/*
 * Password Key Generation
 * Implements PBKDF2 key derivation for secure password-based encryption.
 * Uses SHA-256 with 100,000 iterations for enhanced security.
 */
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

/*
 * Form Event Handlers
 * Manages form submissions and email functionality.
 * Prevents default form submission and creates mailto links.
 */
document.addEventListener('DOMContentLoaded', function () {
    console.group('Form Initialization');
    console.log('Setting up form event handlers');
    
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function (event) {
            event.preventDefault();
            const formData = new FormData(form);
            const email = formData.get('email');
            const subject = encodeURIComponent(formData.get('subject'));
            const body = encodeURIComponent(formData.get('body'));
            const mailtoLink = `mailto:${email}?subject=${subject}&body=${body}`;
            window.location.href = mailtoLink;
            form.reset();
        });
    });
    
    console.groupEnd();
});

/*
 * Main Application Event Handlers
 * Sets up event listeners for core application functionality including:
 * - Socket events
 * - User interactions
 * - Message handling
 * - Typing indicators
 */
document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById("logout-btn").value = "Logout-" + userData.Username;

    await loadPrivateKey();
    loadPublicKey();

    if (Object.keys(clientKeys).length > 0) {
        loadAvailableFriends();
        loadConReceiveFriends();
        loadAccepetdFriends();
    }

    /*
     * Socket Event Handlers
     * Manages real-time communication between users
     */
    socket.on('email_send_notify', function (data) {
        try {
            clientKeys[data['sender']].status = "con_recv";
            saveClientKeys();
            loadConReceiveFriends();
            loadAvailableFriends();
            
            console.group('Email Notification');
            console.log('Sender:', data['sender']);
            console.log('Status: Connection request received');
            console.groupEnd();
        } catch (error) {
            console.error('Email notification error:', error);
        }
    });

    socket.on('email_reply_notify', function (data) {
        try {
            clientKeys[data['sender']].status = "con_reply_recv";
            saveClientKeys();
            loadAvailableFriends();
            loadConReceiveFriends();
            
            console.group('Reply Notification');
            console.log('Sender:', data['sender']);
            console.log('Status: Connection reply received');
            console.groupEnd();
        } catch (error) {
            console.error('Reply notification error:', error);
        }
    });

    /*
     * Message Handler
     * Processes incoming messages, handles decryption,
     * and manages message display and ordering.
     */
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
            console.log('Message from:', data["sender"]);
            console.log('Processing encrypted content...');

            const decryptedMessage = await decryptMessage(privateKey, data["message"]);
            clientKeys[data["sender"]].receivedMessageId += 1;

            console.log('Message ID:', clientKeys[data["sender"]].receivedMessageId);
            console.groupEnd();

            const hasColon = decryptedMessage.includes(':');
            if (hasColon) {
                const [receivedMessageId, receivedMessage] = decryptedMessage.split(/:(.+)/);

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
                console.error('Invalid message format received');
            }
        } catch (error) {
            console.error('Message processing error:', error);
        }
    });

    /*
     * User and Connection Management Events
     * Handles user list updates and connection status changes
     */
    socket.on("allUsers", function (data) {
        for (const [key, email] of Object.entries(data["allClients"])) {
            console.group('User Processing');
            console.log('Processing user:', key);
            console.log('User email:', email);

            if ((!(key in clientKeys)) && (key != username)) {
                clientKeys[key] = {
                    'username': key,
                    'publicKey': '',
                    'email': email,
                    'status': 'available',
                    'sendMessageId': 0,
                    'receivedMessageId': 0
                };
                console.log('New user added to client keys');
            }
            console.groupEnd();
        }
        
        saveClientKeys();
        loadAvailableFriends();
    });

    socket.on('logoutUsers', function (data) {
        console.group('User Logout');
        console.log('Logout user:', data['logoutUser']);
        
        if (chatClient == data['logoutUser']) {
            let ul = document.getElementById("chat-msg");
            let li = document.createElement("li");
            li.appendChild(document.createTextNode(`${data['logoutUser']} - User Logout`));
            li.classList.add("logout_user");
            ul.appendChild(li);
            ul.scrollTop = ul.scrollHeight;
            chatClient = null;
        }
        
        if (data['logoutUser'] in clientKeys) {
            delete clientKeys[data['logoutUser']];
            saveClientKeys();
            loadAvailableFriends();
            loadConReceiveFriends();
            loadAccepetdFriends();
        }
        console.groupEnd();
    });

    socket.on('logout_redirect', function () {
        logout();
    });

    socket.on('error', function (errorData) {
        console.error('Socket Error:', errorData.message);
    });

    /*
     * Chat Interface Event Handlers
     * Manages message sending, typing indicators, and chat history
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

    document.getElementById('clearHistory').onclick = async () => {
        document.getElementById("chat-msg").innerHTML = "";
    };

    /*
     * Typing Indicator Handlers
     * Manages real-time typing status updates
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
            socket.emit('typing', { sender: username, recipient: chatClient });
        }
    });

    document.getElementById("message-input").addEventListener("keyup", function (event) {
        if (event.key === "Enter") {
            socket.emit('stop_typing', { sender: username, recipient: chatClient });
        }
    });

    document.getElementById("message-input").addEventListener("blur", function () {
        socket.emit('stop_typing', { sender: username, recipient: chatClient });
    });

    /*
     * Logout Handler
     * Manages user logout and session cleanup
     */
    document.getElementById('logout-btn').onclick = () => {
        socket.emit('logout', { user_name: username });
        localStorage.clear();
    };

    /*
     * Typing Status Event Handlers
     * Updates UI based on typing indicators
     */
    socket.on('typing', function (data) {
        console.group('Typing Indicator');
        console.log('User typing:', data.sender);
        console.groupEnd();
        
        document.getElementById("typing-indicator").textContent = data.sender + " is typing...";
    });

    socket.on('stop_typing', function (data) {
        console.group('Typing Indicator');
        console.log('User stopped typing:', data.sender);
        console.groupEnd();
        
        document.getElementById("typing-indicator").textContent = "";
    });
});

/*
 * User Initialization
 * Sets up user session and cryptographic keys
 */
async function initiateUser() {
    try {
        username = userData.Username;
        console.group('User Initialization');
        console.log('Initializing user:', username);

        const privateKeyBase64 = localStorage.getItem('privateKey');
        if (privateKeyBase64) {
            await loadPrivateKey();
            console.log('Using existing private key');
        } else {
            publicKey = await generateRSAKeyPair();
            console.log('Generated new key pair');
        }

        loadPublicKey();
        socket.connect();
        
        socket.on("connect", function () {
            socket.emit('user_join', { 
                recipient: userData.Username, 
                email: userData.Email 
            });
        });
        
        console.groupEnd();
    } catch (error) {
        console.error('User initialization error:', error);
    }
}

/*
 * Friend List Management Functions
 * Handles displaying and updating friend lists
 */
function loadAvailableFriends() {
    var friendsList = document.getElementById("friends-list");
    friendsList.innerHTML = "";

    for (const [key, user] of Object.entries(clientKeys)) {
        console.group('Friend Processing');
        console.log('Username:', user['username']);
        console.log('Email:', user['email']);
        console.log('Status:', user['status']);

        let li = document.createElement("li");

        if (user['status'] == 'con_sent') {
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
                <div class="action"><input type="button" style="background-color:rgb(196, 128, 32);" value="Invitation Sent" disabled></div>
            `;
        } else if (user['status'] == 'available') {
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
                <div class="action"><input type="button" name="connect" value="Invite to chat" onclick='openEmailClientWindow(${JSON.stringify(user)}, "${publicKey}")'></div>
            `;
        }

        friendsList.appendChild(li);
        console.groupEnd();
    }
}

/*
 * Connection Request Management
 * Handles pending connections and friend requests
 */
function loadConReceiveFriends() {
    var friendsList = document.getElementById("received-list");
    friendsList.innerHTML = "";

    for (const [key, user] of Object.entries(clientKeys)) {
        console.group('Connection Request Processing');
        console.log('Processing user:', user['username']);
        console.log('Status:', user['status']);
        console.log('Public Key Status:', user['publicKey'] ? 'Available' : 'Not Available');

        let li = document.createElement("li");

        if ((user['status'] == 'con_recv' || user['status'] == 'con_reply_recv') && user['publicKey'] == "") {
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
                <div class="action"><input type="button" name="add_friend" value="Add ParsePhase" onclick='loadReply(${JSON.stringify(user)}, "${publicKey}")'></div>
            `;
        } else if (user['status'] == 'con_recv' && user['publicKey'] != "") {
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
                <div class="action"><input type="button" name="add_friend" value="Send Confirmation" style="background-color:rgb(196, 128, 32);" onclick='loadReply(${JSON.stringify(user)}, "${publicKey}")'></div>
            `;
        }

        friendsList.appendChild(li);
        console.groupEnd();
    }
}

/*
 * Parse Phase Management
 * Handles public key parsing and verification
 */
function OnAddParsePhaseClick(friendObj) {
    const parsePhase = document.getElementById("body_parsephase").value;
    console.group('Parse Phase Processing');
    console.log('Processing parse phase for:', friendObj.username);
    
    const hasColon = parsePhase.includes(':');
    if (hasColon) {
        const [parsePhaseUser, parsePhasePublicKey] = parsePhase.split(/:(.+)/);

        if (parsePhaseUser == friendObj.username) {
            clientKeys[friendObj.username].publicKey = parsePhasePublicKey;
            document.getElementById('email_request_form').innerHTML = '';
            document.getElementById('email_reply_form').innerHTML = '';
            saveClientKeys();
            loadConReceiveFriends();
            loadAccepetdFriends();
            console.log('Public key successfully added');
        } else {
            publicKeyLoadForm(friendObj, true, 'Please Enter Correct Public Key');
            console.log('Public key user mismatch');
        }
    } else {
        publicKeyLoadForm(friendObj, true, 'Please Enter Correct Public Key');
        console.log('Invalid public key format');
    }
    console.groupEnd();
}

/*
 * Accepted Friends Management
 * Handles display and interaction with connected friends
 */
function loadAccepetdFriends() {
    var friendsList = document.getElementById("connections-list");
    friendsList.innerHTML = "";

    for (const [key, user] of Object.entries(clientKeys)) {
        if (user['status'] == 'accepted') {
            console.group('Accepted Friend Processing');
            console.log('Adding accepted friend:', key);
            
            let li = document.createElement("li");
            li.innerHTML = `
                <div class="status-indicator"></div>
                <div class="username">${key}</div>
                <div class="last-active" id="last-active-${key}"></div>
            `;

            li.addEventListener("click", () => {
                if (chatClient != key) {
                    chatClient = key;
                    chatClientPK = user.publicKey;
                    displaySelectFriendMessage(false);

                    let ul = document.getElementById("chat-msg");
                    let li = document.createElement("li");
                    li.appendChild(document.createTextNode(`Chat with - ${chatClient}`));
                    li.classList.add("center_user");
                    ul.appendChild(li);
                    ul.scrollTop = ul.scrollHeight;
                    
                    console.log('Chat initiated with:', key);
                }
            });

            friendsList.appendChild(li);
            console.groupEnd();
        }
    }
}

/*
 * Email Client Window Management
 * Handles email-based connection requests and notifications
 */
function openEmailClientWindow(obj, publicKey) {    
    if(obj.status == 'available') {
        clientKeys[obj.username].status = "con_sent";
        saveClientKeys();
        socket.emit('send_email_notification', { 
            recipient_name: obj.username, 
            notification: "Public Key Request Send" 
        });
        loadAvailableFriends();
    }
    
    const emailWindow = window.open('', '_blank', 'width=600,height=400');    
    const htmlContent = `/* ... HTML content for email window ... */`;
    
    emailWindow.document.write(htmlContent);
    emailWindow.document.close();

    const scriptContent = `/* ... Script content for email window ... */`;
    
    const script = emailWindow.document.createElement('script');
    script.textContent = scriptContent;
    emailWindow.document.body.appendChild(script);
}

/*
 * Message Handling Functions
 * Manages message encryption, sending, and display
 */
async function sendMessage() {
    clientKeys[chatClient].sendMessageId += 1;
    console.group('Message Sending');
    console.log('Sending message to:', chatClient);
    console.log('Message ID:', clientKeys[chatClient].sendMessageId);

    const clientMessageText = document.getElementById('message-input').value;
    const clientMessage = clientKeys[chatClient].sendMessageId + ':' + clientMessageText;
    
    const encryptedMessage = await encryptMessage(chatClientPK, clientMessage);

    if (chatClient && clientMessage.trim() !== "") {
        document.getElementById("message-input").value = "";
        socket.emit('message', { 
            recipient_name: chatClient, 
            message: encryptedMessage 
        });

        isCurrentUser = true;
        let ul = document.getElementById("chat-msg");
        let li = document.createElement("li");
        li.appendChild(document.createTextNode("Me : " + clientMessageText));
        li.classList.add("right-align");
        ul.appendChild(li);
        ul.scrollTop = ul.scrollHeight;
        
        console.log('Message sent successfully');
    } else {
        console.error(clientMessage.trim() === '' ? 'Empty message' : 'No chat client selected');
    }
    console.groupEnd();
}

/*
 * Cryptographic Operations
 * Handles key generation, encryption, and decryption
 */
async function generateRSAKeyPair() {
    console.group('RSA Key Generation');
    console.log('Generating new RSA key pair');
    
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

    privateKey = keyPair.privateKey;
    await savePrivateKey();
    
    publicKey = publicKeyBase64;
    savePublicKey();
    
    console.log('Key pair generated successfully');
    console.groupEnd();
    
    return publicKeyBase64;
}

/*
 * Message Encryption/Decryption Functions
 * Handles secure message exchange
 */
async function encryptMessage(publicKeyBase64, message) {
    try {
        if (typeof publicKeyBase64 !== 'string' || !isBase64(publicKeyBase64)) {
            throw new Error("Invalid public key format");
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
            { name: "RSA-OAEP" },
            publicKey,
            encodedMessage
        );

        return arrayBufferToBase64(encryptedMessage);
    } catch (error) {
        console.error('Encryption error:', error.message);
        throw error;
    }
}

async function decryptMessage(privateKey, encryptedMessage) {
    try {
        const decryptedMessage = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            base64ToArrayBuffer(encryptedMessage)
        );
        return new TextDecoder().decode(decryptedMessage);
    } catch (error) {
        console.error('Decryption error:', error.message);
        throw error;
    }
}

/*
 * Utility Functions
 * Handles base64 conversion and validation
 */
function base64ToArrayBuffer(base64) {
    try {
        if (!isBase64(base64)) {
            throw new Error("Invalid Base64 string");
        }

        const binaryString = window.atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (error) {
        console.error('Base64 conversion error:', error.message);
        throw error;
    }
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function isBase64(str) {
    const base64Pattern = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/;
    return base64Pattern.test(str);
}

/*
 * UI Helper Functions
 * Manages user interface elements and feedback
 */
function displaySelectFriendMessage(visibility) {
    const selectFriend = document.getElementById('select-friend');
    if (visibility) {
        if (!selectFriend.querySelector('p')) {
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

/*
 * Session Management Functions
 * Handles user session and logout operations
 */
function logout() {
    fetch('/logout', {
        method: 'GET',
        credentials: 'same-origin'
    })
    .then(response => {
        if (response.ok) {
            localStorage.clear();
            window.location.href = '/';
            console.log('Logout successful');
        } else {
            console.error('Logout failed');
        }
    })
    .catch(error => {
        console.error('Logout error:', error);
    });
}