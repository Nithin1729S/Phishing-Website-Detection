chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.safe) {
      // Create a div element for the safe popup
      let popup = document.createElement("div");
      popup.id = "safePopup";
      popup.style.position = "fixed";
      popup.style.bottom = "10px";
      popup.style.right = "10px";
      popup.style.padding = "10px 15px";
      popup.style.backgroundColor = "#4CAF50";
      popup.style.color = "white";
      popup.style.borderRadius = "5px";
      popup.style.boxShadow = "0 2px 8px rgba(0,0,0,0.3)";
      popup.style.zIndex = "9999";
      popup.style.fontFamily = "Arial, sans-serif";
      popup.style.fontSize = "14px";
      popup.innerText = `Safe URL: ${message.url}`;
      
      document.body.appendChild(popup);
      
      // Remove the popup after 3 seconds
      setTimeout(() => {
        popup.remove();
      }, 3000);
    }
  });
  