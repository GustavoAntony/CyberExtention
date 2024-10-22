const originalGetContext = HTMLCanvasElement.prototype.getContext;
HTMLCanvasElement.prototype.getContext = function(type, ...args) {
  if (type === '2d' || type === 'webgl') {
    chrome.runtime.sendMessage({ action: 'canvasFingerprint' });
  }
  return originalGetContext.apply(this, [type, ...args]);
};
