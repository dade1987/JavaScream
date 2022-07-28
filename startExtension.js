// eslint-disable-next-line no-unused-expressions
(function () {
  const fuzzerSettings = document.createElement('div')
  fuzzerSettings.style.position = 'fixed'
  fuzzerSettings.style.bottom = '100px'
  fuzzerSettings.style.right = '100px'
  fuzzerSettings.style.backgroundColor = '#e9ecef'
  fuzzerSettings.style.border = '2px solid black'
  fuzzerSettings.style.borderRadius = '5px'
  fuzzerSettings.style.padding = '20px'
  fuzzerSettings.style.fontSize = '20px'
  fuzzerSettings.style.color = 'black'
  fuzzerSettings.style.fontFamily = '-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, Noto Sans, sans-serif'

  document.body.appendChild(fuzzerSettings)

  fuzzerSettings.innerHTML = '<div><h3>Fuzzer Settings</h3></div><div><input style="width:100%;font-size:20px;margin-bottom:20px;" id="attackerIp" type="text" placeholder="Attacker IP" /></div><div><input style="width:100%;font-size:20px;margin-bottom:20px;" id="attackerPort" type="text" placeholder="Attacker Port" /></div><div><input id="xssScanEnabled" type="checkbox" /><label style="padding-left:5px">XSS Scan Enabled</label></div><div><input id="sqliScanEnabled" type="checkbox" /><label style="padding-left:5px">SQLi Scan Enabled</label></div><div><input id="rceScanEnabled" type="checkbox" /><label style="padding-left:5px">RCE Scan Enabled</label></div><div><input id="formFuzzerEnabled" type="checkbox" /><label style="padding-left:5px">FormFuzzer Enabled</label></div>'

  const button = document.createElement('button')
  button.innerText = 'SCAN PAGE'
  button.style.bottom = '100px'
  button.style.right = '200px'
  button.style.backgroundColor = 'black'
  button.style.borderRadius = '5px'
  button.style.padding = '20px'
  button.style.fontSize = '20px'
  button.style.color = 'white'
  button.style.paddingTop = '20px'
  button.style.width = '100%'

  fuzzerSettings.appendChild(button)

  button.addEventListener('click', () => {
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
