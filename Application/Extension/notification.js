const existingNotification = document.getElementById("safe-notification");
if (existingNotification) {
    existingNotification.remove();
}

// Create notification
const notification = document.createElement("div");
notification.id = "safe-notification";
notification.innerHTML = "✅ This website is safe";
notification.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: #2ecc71;
    color: white;
    padding: 10px 15px;
    border-radius: 10px;
    box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);
    font-family: Arial, sans-serif;
    font-size: 14px;
    z-index: 9999;
    transition: opacity 0.5s ease-in-out;
    opacity: 1;
`;

// Append notification
document.body.appendChild(notification);

// Auto-remove after 3 seconds
setTimeout(() => {
    notification.style.opacity = "0";
    setTimeout(() => notification.remove(), 500);
}, 3000);
