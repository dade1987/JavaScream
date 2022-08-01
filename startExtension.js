/* eslint-disable no-undef */
// eslint-disable-next-line no-unused-expressions
(function () {
  $('body').append('<!-- Modal --> <div class="modal fade" id="guiModal" tabindex="-1" aria-labelledby="exampleModalLabel" aria-hidden="true"> <div class="modal-dialog  modal-xl"> <div class="modal-content"> <div class="modal-header"> <h5 class="modal-title" id="exampleModalLabel">Scan Results</h5> <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button> </div> <div class="modal-body"><div class="accordion" id="accordionExample">You must Scan the Page first</div></div> <div class="modal-footer"> <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button> </div> </div> </div> </div> ')

  $('body').append('<div id="jsBugHuntingHelperDiv" style="position:fixed;bottom:100px;right:100px;background-color:#e9ecef;border:2px solid black; border-radius:5px; padding:20px;font-size:20px;color:black;font-family:\'-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, Noto Sans, sans-serif\';"></div>')
  $('#jsBugHuntingHelperDiv').append('<div><h3>Fuzzer Settings</h3></div><div><input style="width:100%;font-size:20px;margin-bottom:20px;" id="attackerIp" type="text" placeholder="Attacker IP" /></div><div><input style="width:100%;font-size:20px;margin-bottom:20px;" id="attackerPort" type="text" placeholder="Attacker Port" /></div><div><input id="xssScanEnabled" type="checkbox" /><label style="padding-left:5px">XSS Scan Enabled</label></div><div><input id="sqliScanEnabled" type="checkbox" /><label style="padding-left:5px">SQLi Scan Enabled</label></div><div><input id="rceScanEnabled" type="checkbox" /><label style="padding-left:5px">RCE Scan Enabled</label></div><div><input id="formFuzzerEnabled" type="checkbox" /><label style="padding-left:5px">FormFuzzer Enabled</label></div>')
  $('#jsBugHuntingHelperDiv').append('<div><button id="openGuiButton" disabled="disabled" type="button" data-bs-toggle="modal" data-bs-target="#guiModal" style="background-color: brown; border-radius: 5px; padding: 20px; font-size: 20px; color: white; width: 100%;">Please Scan</button></div>')
  $('#jsBugHuntingHelperDiv').append('<div><button id="scanButton" type="button" style="background-color: black; border-radius: 5px; padding: 20px; font-size: 20px; color: white; width: 100%;">Scan Page</button></div>')

  $('#jsBugHuntingHelperDiv #scanButton').click(() => {
    const xssScanEnabled = document.getElementById('xssScanEnabled').checked
    const sqliScanEnabled = document.getElementById('sqliScanEnabled').checked
    const rceScanEnabled = document.getElementById('rceScanEnabled').checked
    const formFuzzerEnabled = document.getElementById('formFuzzerEnabled').checked
    const attackerIp = document.getElementById('attackerIp').value
    const attackerPort = document.getElementById('attackerPort').value
    // eslint-disable-next-line no-undef
    jBHH.init(xssScanEnabled, sqliScanEnabled, rceScanEnabled, formFuzzerEnabled, attackerIp, attackerPort)
  })
})()
