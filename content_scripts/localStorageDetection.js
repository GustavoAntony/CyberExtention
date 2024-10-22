if (window.localStorage.length > 0) {
    let storageData = Object.entries(window.localStorage);
    chrome.runtime.sendMessage({ action: 'localStorage', data: storageData });
  }
  