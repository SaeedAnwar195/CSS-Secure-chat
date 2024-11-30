function validateLogin() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    if (username === '' || password === '') {
        const messageContainer = document.querySelector('.message-container');
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message error';
        messageDiv.textContent = 'Username and Password are required for login.';
        
        messageContainer.appendChild(messageDiv);
        
        setTimeout(() => {
            messageDiv.remove();
        }, 3000);
        
        return false;
    }
    return true;
}
