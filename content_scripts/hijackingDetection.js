(function() {
    let hijackingDetected = false;
    
    // Monitorar alterações no comportamento de redirecionamento
    const originalLocationAssign = window.location.assign;
    window.location.assign = function(url) {
      alert('Possível tentativa de hijacking detectada: redirecionamento não autorizado para ' + url);
      hijackingDetected = true;
      return originalLocationAssign.apply(window.location, arguments);
    };
  
    const originalLocationReplace = window.location.replace;
    window.location.replace = function(url) {
      alert('Possível tentativa de hijacking detectada: substituição de URL para ' + url);
      hijackingDetected = true;
      return originalLocationReplace.apply(window.location, arguments);
    };
  
    // Monitorar abertura de janelas popup não solicitadas
    const originalWindowOpen = window.open;
    window.open = function(url, ...args) {
      alert('Tentativa de abrir uma nova janela detectada: ' + url);
      hijackingDetected = true;
      return originalWindowOpen.apply(window, [url, ...args]);
    };
  
    // Enviar resultado para o background script
    if (hijackingDetected) {
      chrome.runtime.sendMessage({ action: 'hijackingDetected' });
    }
  
  })();
  