// il payload funziona passando i parametri originali come array con coppia di valori, url e metodo HTTP all'interno
// e gestisce tutta la richiesta, e testa la risposta
// eslint-disable-next-line no-unused-vars
function Payload (url, type, httpMethod, params, previousAction, payloadString, expectedResult, payloadType, customHeaders, optCookiesEntities) {
  // console.log('a', url, httpMethod, params)

  this.url = url
  this.type = type
  this.httpMethod = httpMethod
  this.params = params
  this.previousAction = previousAction
  this.payloadString = payloadString
  this.expectedResult = expectedResult
  this.payloadType = payloadType
  this.customHeaders = customHeaders
  this.optCookiesEntities = optCookiesEntities

  this.pageRequest = async function () {
    const promises = []
    for (let i = 0; i < this.params.length; i++) {
      promises.push(new Promise((resolve, reject) => {
        // fa il giro di tutti i parametri (nel test 2)
        // si copia i parametri originali, e SOLO nell'indice in cui si trova assegna il payload al parametro

        const modParams = JSON.parse(JSON.stringify(this.params))

        if (modParams[i][0].toLowerCase() !== 'submit') {
          modParams[i][1] += payloadString

          console.log('DBG PAGE REQUEST', modParams[i][0], Object.fromEntries(modParams))

          // eslint-disable-next-line no-undef
          $.ajax(this.url, {
            headers: this.customHeaders,
            type: this.httpMethod,
            data: Object.fromEntries(modParams)
          }).done((data) => {
          // eslint-disable-next-line no-eval
            eval(this.previousAction)
            // eslint-disable-next-line no-eval
            if (eval(this.expectedResult) === true) {
              console.log('DBG PAGE REQUEST TRUE', { url: this.url, httpMethod: this.httpMethod, paramName: modParams[i][0], paramValue: modParams[i][1], payloadType: this.payloadType })
              resolve({ return: true, url: this.url, httpMethod: this.httpMethod, paramName: modParams[i][0], paramValue: modParams[i][1], payloadType: this.payloadType })
            } else {
              resolve({ return: false })
            }
          }).fail(() => {
            resolve({ return: false })
          })
        } else {
          resolve({ return: false })
        }
      })
      )
    }
    // if there is at least one true it means that the payload was successful
    return Promise.allSettled(promises).then((v) => {
    // eslint-disable-next-line array-callback-return
      const a = v.filter((v) => {
        if (v.status === 'fulfilled' && v.value.return === true) { return v.value }
      })

      if (a.length > 0) {
        return a[0].value
      } else {
        return false
      }
    })
  }

  this.cookiesRequest = async function () {
    const promises = []
    for (let i = 0; i < this.optCookiesEntities.length; i++) {
      promises.push(new Promise((resolve, reject) => {
        // fa il giro di tutti i parametri (nel test 2)
        // si copia i parametri originali, e SOLO nell'indice in cui si trova assegna il payload al parametro

        const initialModParams = JSON.parse(JSON.stringify(this.optCookiesEntities))
        const modParams = JSON.parse(JSON.stringify(this.optCookiesEntities))

        // fist set cookie like initial
        initialModParams.forEach((v) => {
          document.cookie = v[0].trim() + '=' + v[1].trim()
          // console.log('SET COOKIE 1', v[0].trim() + '=' + v[1].trim())
        })

        // console.log('SET COOKIE2', document.cookie)

        // then modify one cookie
        modParams[i][1] += payloadString

        // console.log('DBG COOKIES', modParams[i][0].trim(), Object.fromEntries(modParams))

        // console.log('SET COOKIE 3', document.cookie)

        // must set 1 cookie at time
        document.cookie = modParams[i][0].trim() + '=' + modParams[i][1].trim()

        console.log('SET COOKIE', document.cookie)

        // reset initial cookie
        initialModParams.forEach((v) => {
          document.cookie = v[0].trim() + '=' + v[1].trim()
          // console.log('SET COOKIE 5', v[0].trim() + '=' + v[1].trim())
        })

        // console.log('SET COOKIE', document.cookie)

        // eslint-disable-next-line no-undef
        $.ajax(this.url, {
          headers: this.customHeaders,
          type: this.httpMethod,
          data: Object.fromEntries(this.params)
        }).done((data) => {
          // eslint-disable-next-line no-eval
          eval(this.previousAction)
          // eslint-disable-next-line no-eval
          if (eval(this.expectedResult) === true) {
            console.log('DBG COOKIES TRUE', { url: this.url, httpMethod: this.httpMethod, paramName: modParams[i][0], paramValue: modParams[i][1], payloadType: this.payloadType })
            resolve({ return: true, url: this.url, httpMethod: this.httpMethod, paramName: modParams[i][0], paramValue: modParams[i][1], payloadType: this.payloadType })
          } else {
            resolve({ return: false })
          }
        }).fail(() => {
          resolve({ return: false })
        })
      })
      )
    }
    // if there is at least one true it means that the payload was successful
    return Promise.allSettled(promises).then((v) => {
      // eslint-disable-next-line array-callback-return
      const a = v.filter((v) => {
        if (v.status === 'fulfilled' && v.value.return === true) { return v.value }
      })

      // console.log(a)
      if (a.length > 0) {
        return a[0].value
      } else {
        return false
      }
    })
  }

  this.headersRequest = async function () {
    const promises = []
    for (let i = 0; i < this.customHeaders.length; i++) {
      promises.push(new Promise((resolve, reject) => {
        // fa il giro di tutti i parametri (nel test 2)
        // si copia i parametri originali, e SOLO nell'indice in cui si trova assegna il payload al parametro

        const modParams = JSON.parse(JSON.stringify(this.customHeaders))

        modParams[i][1] += payloadString

        console.log('DBG HEADERS', modParams[i][0], Object.fromEntries(modParams))

        // eslint-disable-next-line no-undef
        $.ajax(this.url, {
          headers: Object.fromEntries(modParams),
          type: this.httpMethod,
          data: Object.fromEntries(this.params)
        }).done((data, textStatus, jqXHR) => {
          const httpStatus = jqXHR.status;
          // eslint-disable-next-line no-eval
          eval(this.previousAction)
          // eslint-disable-next-line no-eval
          if (eval(this.expectedResult) === true) {
            console.log('DBG HEADERS TRUE', { url: this.url, httpMethod: this.httpMethod, paramName: modParams[i][0], paramValue: modParams[i][1], payloadType: this.payloadType })
            resolve({ return: true, url: this.url, httpMethod: this.httpMethod, paramName: modParams[i][0], paramValue: modParams[i][1], payloadType: this.payloadType })
          } else {
            resolve({ return: false })
          }
        }).fail(() => {
          resolve({ return: false })
        })
      })
      )
    }
    // if there is at least one true it means that the payload was successful
    return Promise.allSettled(promises).then((v) => {
      // eslint-disable-next-line array-callback-return
      const a = v.filter((v) => {
        if (v.status === 'fulfilled' && v.value.return === true) { return v.value }
      })

      if (a.length > 0) {
        return a[0].value
      } else {
        return false
      }
    })
  }

  switch (this.type) {
    case 'pageParams':
      this.isValidResponse = async function () {
        const response = await this.pageRequest()
        return response
      }
      break
    case 'cookiesParams':
      this.isValidResponse = async function () {
        const response = await this.cookiesRequest()
        return response
      }
      break
    case 'headersParams':
      this.isValidResponse = async function () {
        const response = await this.headersRequest()
        return response
      }
      break
    default:
      alert('Payload Error')
  }
}
