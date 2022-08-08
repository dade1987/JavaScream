/* eslint-disable no-undef */
// eslint-disable-next-line no-unused-expressions
(function () {
  let guiView = ''
  guiView += '<div class="modal fade" id="guiModal" tabindex="-1" aria-labelledby="exampleModalLabel" aria-hidden="true">'
  guiView += '  <div class="modal-dialog  modal-xl">'
  guiView += '    <div class="modal-content">'
  guiView += '      <div class="modal-header">'
  guiView += '        <h5 class="modal-title" id="exampleModalLabel">Scan Results</h5>'
  guiView += '        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>'
  guiView += '      </div>'
  guiView += '      <div class="modal-body">'
  guiView += '        <div class="accordion" id="accordionExample">You must Scan the Page first</div>'
  guiView += '      </div>'
  guiView += '      <div class="modal-footer">'
  guiView += '        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>'
  guiView += '      </div>'
  guiView += '    </div>'
  guiView += '  </div>'
  guiView += '</div>'

  let javaScreamPupupView = ''
  javaScreamPupupView += '<div id="jsBugHuntingHelperDiv" style="z-index:1000000;position:fixed;bottom:10px;right:10px;background-color:#e9ecef;border:2px solid black; border-radius:5px; padding:20px;font-size:16px;color:black;font-family:\'-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, Noto Sans, sans-serif\';">'

  javaScreamPupupView += '  <div class="bigContainer" style="display:none">'

  javaScreamPupupView += '  <div class="pull-right"><a class="minimizeAction" href="javascript:">MIN</a></div>'

  javaScreamPupupView += '  <div><h3>Manual Fuzzer</h3></div>'
  javaScreamPupupView += '  <div><input style="width:100%;font-size:16px;margin-bottom:20px;" id="manualFuzzerUrl" type="text" placeholder="Full URL https://website.com/file.ext" /></div>'
  javaScreamPupupView += '  <div><input style="width:100%;font-size:16px;margin-bottom:20px;" id="manualFuzzerMethod" type="text" placeholder="HTTP Method (GET, POST, ...)" /></div>'
  javaScreamPupupView += '  <div><input style="width:100%;font-size:16px;margin-bottom:20px;" id="manualFuzzerParams" type="text" placeholder=\'Params: {"id":"1", "name":"david" } )\' /></div>'

  javaScreamPupupView += '  <div><h3>Optional Settings</h3></div>'

  javaScreamPupupView += '  <div><input style="width:100%;font-size:16px;margin-bottom:20px;" id="customCookie" type="text" placeholder="Custom Cookie Value PHPSESSID=123" /></div>'
  javaScreamPupupView += '  <div><input style="width:100%;font-size:16px;margin-bottom:20px;" id="customHeaders" type="text" placeholder=\'Additional Headers {"X-Forwarded-For":"203.0.113.195"}\' /></div>'
  javaScreamPupupView += '  <div><input style="width:100%;font-size:16px;margin-bottom:20px;" id="attackerIp" type="text" placeholder="Attacker IP (RCE, SQLi)" /></div>'
  javaScreamPupupView += '  <div><input style="width:100%;font-size:16px;margin-bottom:20px;" id="attackerPort" type="text" placeholder="Attacker Port  (RCE, SQLi)" /></div>'

  javaScreamPupupView += '  <div><h3>Fuzzer Settings</h3></div>'

  javaScreamPupupView += '  <div><input id="xssScanEnabled" type="checkbox" /><label style="padding-left:5px">XSS Scan Enabled</label></div>'
  javaScreamPupupView += '  <div><input id="sqliScanEnabled" type="checkbox" /><label style="padding-left:5px">SQLi Scan Enabled</label></div>'
  javaScreamPupupView += '  <div><input id="rceScanEnabled" type="checkbox" /><label style="padding-left:5px">RCE Scan Enabled</label></div>'
  javaScreamPupupView += '  <div><input id="formFuzzerEnabled" type="checkbox" /><label style="padding-left:5px">FormFuzzer Enabled</label></div>'

  javaScreamPupupView += '  <div><input id="cookiesFuzzerEnabled" type="checkbox" /><label style="padding-left:5px">Cookies Fuzzer Enabled</label></div>'
  javaScreamPupupView += '  <div><input id="headersFuzzerEnabled" type="checkbox" /><label style="padding-left:5px">Custom Headers Fuzzer Enabled</label></div>'

  javaScreamPupupView += '  <div><button id="manualFuzzerButton" type="button" style="background-color: black; border-radius: 5px; padding: 10px; font-size: 20px; color: white; width: 100%;">Manual Fuzz</button></div>'

  javaScreamPupupView += '  <div><button id="scanButton" type="button" style="background-color: black; border-radius: 5px; padding: 10px; font-size: 20px; color: white; width: 100%;">Normal Scan</button></div>'

  javaScreamPupupView += '  <div><button id="spiderButton" type="button" style="background-color: black; border-radius: 5px; padding: 10px; font-size: 20px; color: white; width: 100%;">Spider</button></div>'

  javaScreamPupupView += '  <div><button id="openGuiButton" disabled="disabled" type="button" data-bs-toggle="modal" data-bs-target="#guiModal" style="background-color: brown; border-radius: 5px; padding: 10px; font-size: 20px; color: white; width: 100%;">Please Scan</button></div>'

  javaScreamPupupView += '  </div>'

  javaScreamPupupView += '  <div class="smallContainer">'

  javaScreamPupupView += '  <div class="pull-right"><a href="javascript:" class="maximizeAction">JavaScream</a></div>'

  javaScreamPupupView += '  </div>'

  javaScreamPupupView += '</div>'

  const javaScreamView = guiView + javaScreamPupupView

  $('body').append(javaScreamView)

  $('#jsBugHuntingHelperDiv .minimizeAction').click(() => {
    $('#jsBugHuntingHelperDiv .bigContainer').hide()
    $('#jsBugHuntingHelperDiv .smallContainer').show()
  })

  $('#jsBugHuntingHelperDiv .maximizeAction').click(() => {
    $('#jsBugHuntingHelperDiv .smallContainer').hide()
    $('#jsBugHuntingHelperDiv .bigContainer').show()
  })

  $('#jsBugHuntingHelperDiv #scanButton').click(() => {
    const xssScanEnabled = document.getElementById('xssScanEnabled').checked
    const sqliScanEnabled = document.getElementById('sqliScanEnabled').checked
    const rceScanEnabled = document.getElementById('rceScanEnabled').checked
    const formFuzzerEnabled = document.getElementById('formFuzzerEnabled').checked
    const attackerIp = document.getElementById('attackerIp').value
    const attackerPort = document.getElementById('attackerPort').value
    const customCookie = document.getElementById('customCookie').value
    const customHeaders = document.getElementById('customHeaders').value
    const cookiesFuzzerEnabled = document.getElementById('cookiesFuzzerEnabled').checked
    const headersFuzzerEnabled = document.getElementById('headersFuzzerEnabled').checked
    // eslint-disable-next-line no-undef
    jBHH.init(xssScanEnabled, sqliScanEnabled, rceScanEnabled, formFuzzerEnabled, attackerIp, attackerPort, customCookie, customHeaders, cookiesFuzzerEnabled, headersFuzzerEnabled)
    jBHH.normalScan()
  })

  $('#jsBugHuntingHelperDiv #manualFuzzerButton').click(() => {
    const xssScanEnabled = document.getElementById('xssScanEnabled').checked
    const sqliScanEnabled = document.getElementById('sqliScanEnabled').checked
    const rceScanEnabled = document.getElementById('rceScanEnabled').checked
    const formFuzzerEnabled = document.getElementById('formFuzzerEnabled').checked
    const attackerIp = document.getElementById('attackerIp').value
    const attackerPort = document.getElementById('attackerPort').value
    const manualFuzzerUrl = document.getElementById('manualFuzzerUrl').value
    const manualFuzzerMethod = document.getElementById('manualFuzzerMethod').value
    const manualFuzzerParams = document.getElementById('manualFuzzerParams').value
    const customCookie = document.getElementById('customCookie').value
    const customHeaders = document.getElementById('customHeaders').value
    const cookiesFuzzerEnabled = document.getElementById('cookiesFuzzerEnabled').checked
    const headersFuzzerEnabled = document.getElementById('headersFuzzerEnabled').checked
    // eslint-disable-next-line no-undef
    jBHH.init(xssScanEnabled, sqliScanEnabled, rceScanEnabled, formFuzzerEnabled, attackerIp, attackerPort, customCookie, customHeaders, cookiesFuzzerEnabled, headersFuzzerEnabled)
    jBHH.manualFuzzer(manualFuzzerUrl, manualFuzzerMethod, manualFuzzerParams)
  })

  $('#jsBugHuntingHelperDiv #spiderButton').click(() => {
    const xssScanEnabled = document.getElementById('xssScanEnabled').checked
    const sqliScanEnabled = document.getElementById('sqliScanEnabled').checked
    const rceScanEnabled = document.getElementById('rceScanEnabled').checked
    const formFuzzerEnabled = document.getElementById('formFuzzerEnabled').checked
    const attackerIp = document.getElementById('attackerIp').value
    const attackerPort = document.getElementById('attackerPort').value
    // const manualFuzzerUrl = document.getElementById('manualFuzzerUrl').value
    // const manualFuzzerMethod = document.getElementById('manualFuzzerMethod').value
    // const manualFuzzerParams = document.getElementById('manualFuzzerParams').value
    const customCookie = document.getElementById('customCookie').value
    const customHeaders = document.getElementById('customHeaders').value
    const cookiesFuzzerEnabled = document.getElementById('cookiesFuzzerEnabled').checked
    const headersFuzzerEnabled = document.getElementById('headersFuzzerEnabled').checked
    // eslint-disable-next-line no-undef
    jBHH.init(xssScanEnabled, sqliScanEnabled, rceScanEnabled, formFuzzerEnabled, attackerIp, attackerPort, customCookie, customHeaders, cookiesFuzzerEnabled, headersFuzzerEnabled)
    jBHH.spider()
  })
})()
