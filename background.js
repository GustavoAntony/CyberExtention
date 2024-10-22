let vulnerabilities = {};

function initTabVulnerabilities(tabId) {
  vulnerabilities[tabId] = {
    thirdPartyConnections: new Set(),
    cookies: {
      firstParty: { session: 0, persistent: 0 },
      thirdParty: { session: 0, persistent: 0 }
    },
    localStorageData: 0,
    localStorageDataSize: 0,
    canvasFingerprint: false,
    potentialHijacking: false
  };
}

// Detecta conexões de terceira parte
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    if (details.tabId === -1) return;
    if (!vulnerabilities[details.tabId]) initTabVulnerabilities(details.tabId);

    let url = new URL(details.url);
    let domain = url.hostname;

    if (details.initiator && !details.initiator.includes(domain)) {
      vulnerabilities[details.tabId].thirdPartyConnections.add(domain);
    }

    // Detecção de potencial hijacking (exemplo simples)
    if (url.pathname.includes('eval(') || url.pathname.includes('document.write(')) {
      vulnerabilities[details.tabId].potentialHijacking = true;
    }
  },
  { urls: ["<all_urls>"] }
);

// Detecta cookies
chrome.cookies.onChanged.addListener(function(changeInfo) {
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (tabs[0] && tabs[0].url.includes(changeInfo.cookie.domain)) {
      let tabId = tabs[0].id;
      if (!vulnerabilities[tabId]) initTabVulnerabilities(tabId);

      let cookieType = changeInfo.cookie.domain.startsWith('.') ? 'thirdParty' : 'firstParty';
      let cookieDuration = changeInfo.cookie.session ? 'session' : 'persistent';

      if (!changeInfo.removed) {
        vulnerabilities[tabId].cookies[cookieType][cookieDuration]++;
      }
    }
  });
});

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (changeInfo.status === 'complete') {
    chrome.tabs.executeScript(tabId, {
      code: `
        // Função para verificar se o canvas está sendo usado para fingerprinting
        function isCanvasFingerprinting() {
          let canvas = document.createElement('canvas');
          let context = canvas.getContext('2d');

          // Desenha algo específico, normalmente usado em fingerprinting
          context.textBaseline = "top";
          context.font = "14px 'Arial'";
          context.fillStyle = "#f60";
          context.fillRect(125, 1, 62, 20);
          context.fillStyle = "#069";
          context.fillText("fingerprinting", 2, 15);
          context.strokeStyle = "rgba(102, 204, 0, 0.7)";
          context.strokeRect(125, 1, 62, 20);

          // Obtem os dados do canvas
          let dataURL = canvas.toDataURL();

          // Verifica se foi alterado ou manipulado
          return dataURL;
        }

        let canvasFingerprinting = false;
        let originalToDataURL = HTMLCanvasElement.prototype.toDataURL;

        HTMLCanvasElement.prototype.toDataURL = function() {
          let dataURL = isCanvasFingerprinting();
          // Condição para detectar fingerprinting baseado em manipulação de canvas
          if (dataURL) {
            canvasFingerprinting = true;
          }
          return originalToDataURL.apply(this, arguments);
        };

        // Simula uma ação que poderia usar canvas fingerprinting
        let canvas = document.createElement('canvas');
        canvas.getContext('2d');
        canvas.toDataURL();
        
        // Restaura o método original
        HTMLCanvasElement.prototype.toDataURL = originalToDataURL;
        
        // Retorna o status da detecção
        ({ canvasFingerprinting: canvasFingerprinting });
      `
    }, function(results) {
      if (results && results[0]) {
        vulnerabilities[tabId].canvasFingerprint = results[0].canvasFingerprinting;
      }
    });
  }
});

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (changeInfo.status === 'complete') {
    chrome.tabs.executeScript(tabId, {
      code: `
        // Função para calcular o tamanho do localStorage
        function calculateLocalStorageSize() {
          let totalSizeChars = 0;
          let totalSizeBytes = 0;
          console.log("Tamanho do localStorage:", localStorage.length); // Log para verificar o tamanho
          for (let i = 0; i < localStorage.length; i++) {
            let key = localStorage.key(i);
            let value = localStorage.getItem(key);
            console.log("Chave:", key, "Valor:", value); // Log de cada chave e valor
            
            // Calcula o tamanho em caracteres
            totalSizeChars += key.length + value.length;

            // Calcula o tamanho em bytes usando Blob
            let sizeInBytes = new Blob([key + value]).size;
            totalSizeBytes += sizeInBytes;
          }
          return { totalSizeChars: totalSizeChars, totalSizeBytes: totalSizeBytes };
        }

        // Detecção de localStorage
        let localStorageSize = calculateLocalStorageSize();
        
        // Retorna os resultados em um objeto
        ({ 
          localStorageSizeChars: localStorageSize.totalSizeChars, 
          localStorageSizeBytes: localStorageSize.totalSizeBytes
        });
      `
    }, function(results) {
      if (results && results[0]) {
        vulnerabilities[tabId].localStorageData = results[0].localStorageSizeChars;
        vulnerabilities[tabId].localStorageDataSize = results[0].localStorageSizeBytes;
      }
    });
  }
});


// // Detecta localStorage e Canvas Fingerprinting
// chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
//   if (changeInfo.status === 'complete') {
//     chrome.tabs.executeScript(tabId, {
//       code: `
//         // Função para calcular o tamanho do localStorage
//         function calculateLocalStorageSize() {
//           let totalSize = 0;
//           console.log("Tamanho do localStorage:", localStorage.length); // Log para verificar o tamanho
//           for (let i = 0; i < localStorage.length; i++) {
//             let key = localStorage.key(i);
//             let value = localStorage.getItem(key);
//             console.log("Chave:", key, "Valor:", value); // Log de cada chave e valor
//             totalSize += key.length + value.length; // Tamanho total em caracteres
//           }
//           return totalSize; // Retorna tamanho total em caracteres
//         }

//         // Detecção de localStorage
//         let localStorageSize = calculateLocalStorageSize();
        
//         // Detecção simples de Canvas Fingerprinting
//         let canvasFingerprinting = false;
//         let originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        
//         HTMLCanvasElement.prototype.toDataURL = function() {
//           canvasFingerprinting = true;
//           return originalToDataURL.apply(this, arguments);
//         };
        
//         // Simula uma ação que poderia usar canvas fingerprinting
//         let canvas = document.createElement('canvas');
//         canvas.getContext('2d');
//         canvas.toDataURL();
        
//         // Restaura o método original
//         HTMLCanvasElement.prototype.toDataURL = originalToDataURL;
        
//         // Retorna os resultados em um objeto
//         ({ localStorageSize: localStorageSize, canvasFingerprinting: canvasFingerprinting });
//       `
//     }, function(results) {
//       if (results && results[0]) {
//         vulnerabilities[tabId].localStorageData = results[0].localStorageSize;
//         vulnerabilities[tabId].canvasFingerprint = results[0].canvasFingerprinting;
//       }
//     });
//   }
// });



// Limpa dados quando uma tab é fechada
chrome.tabs.onRemoved.addListener(function(tabId) {
  delete vulnerabilities[tabId];
});

// Converte a pontuação numérica em classificação de letras
function getPrivacyScoreLetter(score) {
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B+';
  if (score >= 60) return 'B';
  if (score >= 50) return 'C+';
  if (score >= 40) return 'C';
  if (score >= 30) return 'D+';
  if (score >= 20) return 'D';
  return 'F';
}

// Calcula a pontuação de privacidade
function calculatePrivacyScore(tabData) {
  let score = 100;

  // Penaliza por conexões de terceiros
  score -= Math.min(tabData.thirdPartyConnections.size * 5, 30);

  // Penaliza por cookies
  let totalCookies = Object.values(tabData.cookies).reduce((sum, type) => 
    sum + Object.values(type).reduce((s, count) => s + (count || 0), 0), 0);
  score -= Math.min(totalCookies * 2, 20);

  // Penaliza por uso de localStorage
  score -= Math.min(Math.floor(tabData.localStorageData / 1024), 10);

  // Penaliza por Canvas Fingerprinting
  if (tabData.canvasFingerprint) score -= 20;

  // Penaliza por potencial hijacking
  if (tabData.potentialHijacking) score -= 20;

  // Retorna a classificação em letras
  return {
    numericScore: Math.max(0, score),
    letterScore: getPrivacyScoreLetter(Math.max(0, score))
  };
}


// Envia as vulnerabilidades e a pontuação para o popup quando solicitado
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getVulnerabilities') {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      if (tabs[0] && vulnerabilities[tabs[0].id]) {
        let tabData = vulnerabilities[tabs[0].id];
        let privacyScore = calculatePrivacyScore(tabData);
        sendResponse({...tabData, privacyScore: privacyScore});
      } else {
        sendResponse({});
      }
    });
    return true;  // Indica que a resposta será assíncrona
  }
});