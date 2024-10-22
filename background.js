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
      
      // Usa 'initiator' ou 'originUrl' para garantir o domínio correto
      const initiatorDomain = details.initiator ? new URL(details.initiator).hostname : 
                             (details.originUrl ? new URL(details.originUrl).hostname : '');

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

    const cookieType = changeInfo.cookie.domain.startsWith('.') ? 'thirdParty' : 'firstParty';
    const cookieDuration = changeInfo.cookie.session ? 'session' : 'persistent';

    // Atualiza a contagem de cookies
    if (!changeInfo.removed) {
      if (!tabData.cookies[cookieType][cookieDuration]) {
        tabData.cookies[cookieType][cookieDuration] = 0; // Inicializa se necessário
      }
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

    // Reinicializa a contagem de cookies para garantir que não sejam contados duas vezes
    tabData.cookies = {
      firstParty: { session: 0, persistent: 0 },
      thirdParty: { session: 0, persistent: 0 }
    };

    // Obtém todos os cookies da aba ativa
    chrome.cookies.getAll({ url: tabs[0].url }, function(cookies) {
      cookies.forEach(cookie => {
        const cookieType = cookie.domain.startsWith('.') ? 'thirdParty' : 'firstParty';
        const cookieDuration = cookie.session ? 'session' : 'persistent';
        
        // Incrementa a contagem de cookies
        if (!tabData.cookies[cookieType][cookieDuration]) {
          tabData.cookies[cookieType][cookieDuration] = 0; // Inicializa se necessário
        }
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
          for (let i = 0; i < localStorage.length; i++) {
            let key = localStorage.key(i);
            let value = localStorage.getItem(key);
            totalSizeChars += key.length + value.length;
            totalSizeBytes += new Blob([key + value]).size;
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



const injectScript = `
// Verificação de conexões de terceiros
(function() {
  const originalFetch = window.fetch;
  const originalXhrOpen = XMLHttpRequest.prototype.open;

  // Hook para fetch API
  window.fetch = function(...args) {
    const url = new URL(args[0]);
    const domain = url.hostname;
    const initiatorDomain = window.location.hostname;
    
    if (domain !== initiatorDomain) {
      console.log("Third-party connection detected via fetch:", domain);
      window.postMessage({
        type: 'THIRD_PARTY_CONNECTION',
        detail: { method: 'fetch', domain: domain }
      }, '*');
    }
    
    return originalFetch.apply(this, args);
  };

  // Hook para XMLHttpRequest
  XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
    const parsedUrl = new URL(url);
    const domain = parsedUrl.hostname;
    const initiatorDomain = window.location.hostname;

    if (domain !== initiatorDomain) {
      console.log("Third-party connection detected via XHR:", domain);
      window.postMessage({
        type: 'THIRD_PARTY_CONNECTION',
        detail: { method: 'xhr', domain: domain }
      }, '*');
    }

    return originalXhrOpen.apply(this, arguments);
  };
})();

// Verificação aprimorada de Canvas Fingerprinting
(function() {
  let canvasOperations = {
    toDataURL: 0,
    getImageData: 0,
    fillText: 0,
    font: 0
  };
  
  const resetCounters = () => {
    setTimeout(() => {
      canvasOperations = {
        toDataURL: 0,
        getImageData: 0,
        fillText: 0,
        font: 0
      };
    }, 1000);
  };

  // Monitor toDataURL
  const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function(...args) {
    canvasOperations.toDataURL++;
    
    if (canvasOperations.toDataURL > 2) {
      window.postMessage({
        type: 'CANVAS_FINGERPRINT_DETECTED',
        detail: 'Multiple toDataURL calls detected'
      }, '*');
    }
    
    const result = originalToDataURL.apply(this, args);
    resetCounters();
    return result;
  };

  // Monitor getContext and its operations
  const originalGetContext = HTMLCanvasElement.prototype.getContext;
  HTMLCanvasElement.prototype.getContext = function(contextType, ...args) {
    const context = originalGetContext.call(this, contextType, ...args);
    
    if (contextType === '2d') {
      // Monitor fillText
      const originalFillText = context.fillText;
      context.fillText = function(text, x, y, maxWidth) {
        canvasOperations.fillText++;
        
        // Detect common fingerprinting patterns
        const suspiciousPatterns = [
          text.includes('👆'),
          text.includes('mmmmm'),
          text.includes('Cwm fjordbank'),
          text.includes('Arial'),
          text.length === 1,
          typeof text === 'number'
        ];
        
        if (suspiciousPatterns.some(pattern => pattern) || canvasOperations.fillText > 3) {
          window.postMessage({
            type: 'CANVAS_FINGERPRINT_DETECTED',
            detail: 'Suspicious fillText pattern detected'
          }, '*');
        }
        
        return originalFillText.apply(this, arguments);
      };

      // Monitor getImageData
      const originalGetImageData = context.getImageData;
      context.getImageData = function(...args) {
        canvasOperations.getImageData++;
        
        if (canvasOperations.getImageData > 2) {
          window.postMessage({
            type: 'CANVAS_FINGERPRINT_DETECTED',
            detail: 'Multiple getImageData calls detected'
          }, '*');
        }
        
        return originalGetImageData.apply(this, arguments);
      };

      // Monitor font property
      let fontDescriptor = Object.getOwnPropertyDescriptor(context.__proto__, 'font');
      Object.defineProperty(context, 'font', {
        get: function() {
          return fontDescriptor.get.call(this);
        },
        set: function(value) {
          canvasOperations.font++;
          
          if (canvasOperations.font > 3) {
            window.postMessage({
              type: 'CANVAS_FINGERPRINT_DETECTED',
              detail: 'Multiple font changes detected'
            }, '*');
          }
          
          return fontDescriptor.set.call(this, value);
        }
      });
    }
    
    return context;
  };
})();

// Verificação aprimorada de Hijacking
(function() {
  let suspiciousOperations = {
    eval: 0,
    documentWrite: 0,
    locationChanges: 0,
    windowOpen: 0
  };

  const DETECTION_WINDOW = 1000; // 1 second window
  const SUSPICIOUS_THRESHOLD = 3;

  function resetOperations() {
    setTimeout(() => {
      suspiciousOperations = {
        eval: 0,
        documentWrite: 0,
        locationChanges: 0,
        windowOpen: 0
      };
    }, DETECTION_WINDOW);
  }

  function detectSuspiciousPattern(operation, detail) {
    suspiciousOperations[operation]++;
    
    if (suspiciousOperations[operation] >= SUSPICIOUS_THRESHOLD) {
      window.postMessage({
        type: 'POTENTIAL_HIJACKING',
        detail: detail
      }, '*');
      resetOperations();
    }
  }

  // Monitor eval
  const originalEval = window.eval;
  window.eval = function(code) {
    detectSuspiciousPattern('eval', {
      type: 'eval',
      message: 'Multiple eval calls detected',
      sample: code.substring(0, 100) // Capture first 100 chars for analysis
    });
    
    // Detect suspicious patterns in eval code
    const suspiciousPatterns = [
      /document\.cookie/i,
      /localStorage/i,
      /sessionStorage/i,
      /window\.location/i,
      /\\.\\+/  // Regex for string concatenation often used in obfuscation
    ];
    
    if (suspiciousPatterns.some(pattern => pattern.test(code))) {
      window.postMessage({
        type: 'POTENTIAL_HIJACKING',
        detail: 'Suspicious eval content detected'
      }, '*');
    }
    
    return originalEval.apply(this, arguments);
  };

  // Monitor document.write
  const originalWrite = document.write;
  const originalWriteln = document.writeln;
  
  document.write = function(content) {
    detectSuspiciousPattern('documentWrite', {
      type: 'write',
      message: 'document.write detected',
      content: content.substring(0, 100)
    });
    
    // Check for suspicious content
    if (content.includes('<script') || content.includes('javascript:')) {
      window.postMessage({
        type: 'POTENTIAL_HIJACKING',
        detail: 'Suspicious document.write content detected'
      }, '*');
    }
    
    return originalWrite.apply(this, arguments);
  };
  
  document.writeln = function(content) {
    detectSuspiciousPattern('documentWrite', {
      type: 'writeln',
      message: 'document.writeln detected',
      content: content.substring(0, 100)
    });
    return originalWriteln.apply(this, arguments);
  };

  // Monitor location changes
  ['assign', 'replace', 'href'].forEach(prop => {
    let original = Object.getOwnPropertyDescriptor(window.location, prop);
    if (original && original.set) {
      Object.defineProperty(window.location, prop, {
        set: function(value) {
          detectSuspiciousPattern('locationChanges', {
            type: 'location',
            method: prop,
            destination: value
          });
          return original.set.call(this, value);
        },
        get: original.get
      });
    }
  });

  // Monitor window.open
  const originalOpen = window.open;
  window.open = function(url, name, specs) {
    detectSuspiciousPattern('windowOpen', {
      type: 'window.open',
      url: url,
      name: name
    });
    
    // Check for suspicious patterns in popup specs
    if (specs && (
      specs.includes('fullscreen') ||
      specs.includes('width=screen.width') ||
      specs.includes('height=screen.height')
    )) {
      window.postMessage({
        type: 'POTENTIAL_HIJACKING',
        detail: 'Suspicious popup parameters detected'
      }, '*');
    }
    
    return originalOpen.apply(this, arguments);
  };
})();
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

  // Penalizações para conexões de terceiros
  let thirdPartyPenalty = Math.min(tabData.thirdPartyConnections.size * 2, 20);
  score -= thirdPartyPenalty;

  // Penalizações para cookies
  const totalCookies = Object.values(tabData.cookies).reduce((sum, type) => 
    sum + Object.values(type).reduce((s, count) => s + (count || 0), 0), 0);
  let cookiesPenalty = Math.min(totalCookies * 1, 20);
  score -= cookiesPenalty;

  // Penalizações para localStorage
  let localStoragePenalty = Math.min(Math.floor(tabData.localStorageData / 1024) * 3, 15);
  score -= localStoragePenalty;

  // Penalizações por canvas fingerprinting
  if (tabData.canvasFingerprint) {
    score -= 10;
  }

  // Penalizações por potencial hijacking
  if (tabData.potentialHijacking) {
    score -= 15;
  }

  // Limitar a pontuação a um mínimo de 0
  let finalScore = Math.max(0, score);
  let letterScore = getPrivacyScoreLetter(finalScore);

  return {
    numericScore: finalScore,
    letterScore: letterScore
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