// warning.js

// Parse the original URL from the query string.
const urlParams = new URLSearchParams(window.location.search);
const originalUrl = urlParams.get("originalUrl");

document.getElementById("goBack").addEventListener("click", () => {
  let newTab = window.open("https://www.google.com", "_blank"); // Open Google in a new tab
  window.close(); // Close the current tab
});


// When the user clicks "Continue", send a message to the background script to bypass the warning.
document.getElementById("continue").addEventListener("click", () => {
  chrome.runtime.sendMessage({ action: "bypass", originalUrl: originalUrl }, (response) => {
    console.log("Bypass message sent. Response:", response);
  });
});
