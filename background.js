let vulnerabilities = new Map();

function initTabVulnerabilities(tabId) {
  if (!vulnerabilities.has(tabId)) {
    vulnerabilities.set(tabId, {
      thirdPartyConnections: new Set(),
      cookies: {
        firstParty: { session: 0, persistent: 0 },
        thirdParty: { session: 0, persistent: 0 },
        total: 0 // Adicionado para contar o total de cookies
      },
      localStorageData: 0,
      localStorageDataSize: 0,
      canvasFingerprint: false,
      potentialHijacking: false,
      lastUpdate: Date.now()
    });
  }
  return vulnerabilities.get(tabId);
}

// Listener para requisições
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    if (details.tabId === -1) return;

    let tabData = vulnerabilities.get(details.tabId);
    if (!tabData) {
      tabData = initTabVulnerabilities(details.tabId);
    }

    try {
      const url = new URL(details.url);
      const domain = url.hostname;
      const initiatorDomain = details.initiator ? new URL(details.initiator).hostname : '';

      if (initiatorDomain && domain !== initiatorDomain) {
        tabData.thirdPartyConnections.add(domain);
      }

      if (url.pathname.includes('eval(') || url.pathname.includes('document.write(')) {
        tabData.potentialHijacking = true;
      }
    } catch (e) {
      console.error('Error processing request:', e);
    }
  },
  { urls: ["<all_urls>"] }
);

// Listener de cookies otimizado
chrome.cookies.onChanged.addListener(function(changeInfo) {
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (!tabs[0]) return;

    const tabId = tabs[0].id;
    let tabData = vulnerabilities.get(tabId);
    if (!tabData) {
      tabData = initTabVulnerabilities(tabId);
    }

    console.log(changeInfo);

    const cookieType = changeInfo.cookie.domain.startsWith('.') ? 'thirdParty' : 'firstParty';
    const cookieDuration = changeInfo.cookie.session ? 'session' : 'persistent';

    // Atualiza a contagem de cookies
    if (!changeInfo.removed) {
      tabData.cookies[cookieType][cookieDuration]++;
    } else if (tabData.cookies[cookieType][cookieDuration] > 0) {
      tabData.cookies[cookieType][cookieDuration]--;
    }
  });
});

// Função para capturar todos os cookies da aba ativa
function captureCookies() {
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (!tabs[0]) return;

    const tabId = tabs[0].id;
    let tabData = vulnerabilities.get(tabId);
    if (!tabData) {
      tabData = initTabVulnerabilities(tabId);
    }

    // Obtém todos os cookies da aba ativa
    chrome.cookies.getAll({ url: tabs[0].url }, function(cookies) {
      cookies.forEach(cookie => {
        console.log(cookie);
        const cookieType = cookie.domain.startsWith('.') ? 'thirdParty' : 'firstParty';
        const cookieDuration = cookie.session ? 'session' : 'persistent';
        tabData.cookies[cookieType][cookieDuration]++;
      });

      console.log(`Cookies capturados para a aba ${tabId}:`, tabData.cookies);
    });
  });
}

// Chama a função captureCookies quando a aba é atualizada ou ativada
chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (changeInfo.status === 'complete') {
    captureCookies(); // Captura cookies após o carregamento da aba

    // Adiciona o listener para calcular o tamanho do localStorage
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
        let tabData = initTabVulnerabilities(tabId); // Inicializa os dados da aba, se necessário
        tabData.localStorageData = results[0].localStorageSizeChars;
        tabData.localStorageDataSize = results[0].localStorageSizeBytes;
      }
    });
  }
});

// Script de injeção para verificações do cliente
const injectScript = `
// ... seu código de injeção aqui ...
`;

// Cálculo de pontuação
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

function calculatePrivacyScore(tabData) {
  let score = 100;

  // Penalizações
  score -= Math.min(tabData.thirdPartyConnections.size * 5, 30);
  
  const totalCookies = Object.values(tabData.cookies).reduce((sum, type) => 
    sum + Object.values(type).reduce((s, count) => s + (count || 0), 0), 0);
  score -= Math.min(totalCookies * 2, 20);
  
  score -= Math.min(Math.floor(tabData.localStorageData / 1024), 10);
  if (tabData.canvasFingerprint) score -= 20;
  if (tabData.potentialHijacking) score -= 20;

  return {
    numericScore: Math.max(0, score),
    letterScore: getPrivacyScoreLetter(Math.max(0, score))
  };
}

// Handler de mensagens
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getVulnerabilities') {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      if (!tabs[0]) {
        sendResponse({});
        return;
      }
      
      const tabId = tabs[0].id;
      let tabData = vulnerabilities.get(tabId);
      
      if (!tabData) {
        tabData = initTabVulnerabilities(tabId);
        checkTabPrivacy(tabId);
      }

      const response = {
        thirdPartyConnections: Array.from(tabData.thirdPartyConnections),
        cookies: tabData.cookies,
        localStorageData: tabData.localStorageData,
        localStorageDataSize: tabData.localStorageDataSize,
        canvasFingerprint: tabData.canvasFingerprint,
        potentialHijacking: tabData.potentialHijacking,
        privacyScore: calculatePrivacyScore(tabData)
      };

      sendResponse(response);
    });
    return true;
  }
});
