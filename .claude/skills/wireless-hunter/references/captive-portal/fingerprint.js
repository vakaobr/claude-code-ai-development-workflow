/* Client-side device fingerprint for the awareness demo.
   Runs in the visitor's browser and fills any <table class="devinfo">.
   DISPLAY-ONLY: nothing here is sent to or stored by the server.
   A real malicious page would exfiltrate exactly this - that's the lesson. */
(function () {
  function esc(s){return String(s).replace(/[<>&]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;'}[c];});}
  function render(rows){
    var html = rows.map(function(r){return '<tr><td>'+r[0]+'</td><td>'+r[1]+'</td></tr>';}).join('');
    document.querySelectorAll('table.devinfo tbody').forEach(function(tb){tb.innerHTML = html;});
  }
  function gpu(){
    try{
      var c=document.createElement('canvas');
      var gl=c.getContext('webgl')||c.getContext('experimental-webgl');
      var d=gl.getExtension('WEBGL_debug_renderer_info');
      return esc(gl.getParameter(d.UNMASKED_RENDERER_WEBGL));
    }catch(e){return ' - ';}
  }
  function archStr(a,b){
    if(!a) return '';
    if(a==='x86') return 'x86-'+(b||'64');
    return a+(b||'');                 // arm + 64 -> arm64
  }
  function build(os, browser){
    var n=navigator, s=screen, tz='';
    try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone;}catch(e){}
    var dpr=window.devicePixelRatio||1;
    var resW=Math.round(s.width*dpr), resH=Math.round(s.height*dpr);
    render([
      ['Operating system', esc(os)],
      ['Browser', esc(browser)],
      ['Device', (n.maxTouchPoints>1?'Touch / mobile':'Desktop')],
      ['Automation', (n.webdriver?'detected (bot)':'none (human)')],
      ['Screen resolution', resW+'×'+resH],
      ['Timezone', esc(tz||' - ')],
      ['Language', esc(n.language||' - ')+((n.languages&&n.languages.length>1)?' ('+esc(n.languages.join(', '))+')':'')],
      ['GPU', gpu()],
      ['CPU cores', (n.hardwareConcurrency?n.hardwareConcurrency+' (approx)':' - ')]
    ]);
  }
  if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues){
    navigator.userAgentData.getHighEntropyValues(
      ['platform','platformVersion','fullVersionList','architecture','bitness'])
      .then(function(d){
        var list=(d.fullVersionList||navigator.userAgentData.brands||[])
                   .filter(function(b){return !/Not.?A.?Brand/i.test(b.brand);});
        // prefer a real brand (Google Chrome / Edge / Brave / Opera) over generic "Chromium"
        var pick=list.filter(function(b){return !/Chromium/i.test(b.brand);})[0] || list[0];
        var browser = pick ? (pick.brand+' '+(pick.version||'')) : navigator.userAgent;
        var os = (d.platform||' - ') + (d.platformVersion?(' '+d.platformVersion):'');
        var a = archStr(d.architecture, d.bitness);
        if(a) os += ' · ' + a;
        build(os, browser);
      }).catch(function(){build(navigator.platform||' - ', navigator.userAgent);});
  } else {
    var ua=navigator.userAgent, os=' - ', b=ua, m;
    if(/Windows NT 10/.test(ua))os='Windows 10/11';
    else if(/Mac OS X/.test(ua))os='macOS';
    else if(/Android/.test(ua))os='Android';
    else if(/iPhone|iPad|iOS/.test(ua))os='iOS';
    else if(/Linux/.test(ua))os='Linux';
    m=ua.match(/(Edg|OPR|Chrome|Firefox|Safari)\/([\d.]+)/);
    if(m)b=({Edg:'Edge',OPR:'Opera'}[m[1]]||m[1])+' '+m[2];
    build(os, b);
  }
})();
