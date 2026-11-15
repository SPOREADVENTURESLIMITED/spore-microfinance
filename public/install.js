let deferredInstall=null;
const installButtons=()=>document.querySelectorAll('[data-install-app]');
function showInstallButtons(){installButtons().forEach(button=>button.hidden=false)}
window.addEventListener('beforeinstallprompt',event=>{event.preventDefault();deferredInstall=event;showInstallButtons()});
window.addEventListener('appinstalled',()=>{deferredInstall=null;installButtons().forEach(button=>{button.textContent='App installed';button.disabled=true})});
document.addEventListener('DOMContentLoaded',()=>{
 showInstallButtons();
 installButtons().forEach(button=>button.addEventListener('click',async()=>{
  if(deferredInstall){deferredInstall.prompt();const choice=await deferredInstall.userChoice;if(choice?.outcome==='accepted')button.textContent='Installing…';deferredInstall=null;return;}
  const ios=/iphone|ipad|ipod/i.test(navigator.userAgent);
  if(ios&&!window.navigator.standalone){alert('To install Spore Microfinance on iPhone or iPad: tap the Share button in Safari, then choose “Add to Home Screen”, and tap Add.');return;}
  if(window.matchMedia('(display-mode: standalone)').matches){alert('Spore Microfinance is already running as an installed app.');return;}
  alert('To install Spore Microfinance, open your browser menu and choose “Install app” or “Add to Home screen”. On a computer, use the install icon in the browser address bar when available.');
 }));
 if('serviceWorker' in navigator)window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));
});