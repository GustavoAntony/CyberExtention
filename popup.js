document.addEventListener('DOMContentLoaded', function() {
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      let currentTab = tabs[0];
      let currentDomain = new URL(currentTab.url).hostname;

      chrome.runtime.sendMessage({action: 'getVulnerabilities'}, function(response) {
          let container = document.getElementById('vulnerabilities-container');

          if (response && Object.keys(response).length > 0) {
              // Exibir pontuação de privacidade
              let scoreElement = document.createElement('h2');
              scoreElement.textContent = `Privacy Score: ${response.privacyScore.numericScore}/100 (${response.privacyScore.letterScore})`;
              container.appendChild(scoreElement);

              // Exibir conexões de terceiros
              let thirdPartyElement = document.createElement('p');
              thirdPartyElement.textContent = `Third-party connections: ${response.thirdPartyConnections.length}`;
              container.appendChild(thirdPartyElement);

              // Botão para mostrar todas as conexões de terceiros
              let showThirdPartyBtn = document.createElement('button');
              showThirdPartyBtn.textContent = 'Show Third-party Connections';
              container.appendChild(showThirdPartyBtn);

              // Lista de conexões de terceiros, inicialmente escondida
              let thirdPartyList = document.createElement('ul');
              thirdPartyList.style.display = 'none';
              response.thirdPartyConnections.forEach(connection => {
                  let li = document.createElement('li');
                  li.textContent = connection;
                  thirdPartyList.appendChild(li);
              });
              container.appendChild(thirdPartyList);

              // Função para exibir ou esconder a lista ao clicar no botão
              showThirdPartyBtn.addEventListener('click', function() {
                  if (thirdPartyList.style.display === 'none') {
                      thirdPartyList.style.display = 'block';
                      showThirdPartyBtn.textContent = 'Hide Third-party Connections';
                  } else {
                      thirdPartyList.style.display = 'none';
                      showThirdPartyBtn.textContent = 'Show Third-party Connections';
                  }
              });

              // Exibir cookies
              let cookiesElement = document.createElement('p');
              let totalCookies = Object.values(response.cookies).reduce((sum, type) => 
                  sum + Object.values(type).reduce((s, count) => s + count, 0), 0);
              cookiesElement.textContent = `Total cookies: ${totalCookies}`;
              container.appendChild(cookiesElement);

              let cookieDetails = document.createElement('ul');
              for (let party in response.cookies) {
                  for (let duration in response.cookies[party]) {
                      let li = document.createElement('li');
                      li.textContent = `${party} ${duration}: ${response.cookies[party][duration]}`;
                      cookieDetails.appendChild(li);
                  }
              }
              container.appendChild(cookieDetails);

              // Exibir uso de localStorage
              let storageElement = document.createElement('p');
              storageElement.textContent = `Local storage usage: ${response.localStorageData} caracteres, (${response.localStorageDataSize}) bytes`;
              container.appendChild(storageElement);

              // Exibir detecção de Canvas Fingerprinting
              let canvasElement = document.createElement('p');
              canvasElement.textContent = `Canvas Fingerprinting detected: ${response.canvasFingerprint ? 'Yes' : 'No'}`;
              container.appendChild(canvasElement);

              // Exibir potencial hijacking
              let hijackingElement = document.createElement('p');
              hijackingElement.textContent = `Potential hijacking detected: ${response.potentialHijacking ? 'Yes' : 'No'}`;
              container.appendChild(hijackingElement);

          } else {
              container.textContent = 'No data available for the current domain.';
          }
      });
  });
});

