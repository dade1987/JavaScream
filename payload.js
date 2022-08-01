// il payload funziona passando i parametri originali come array con coppia di valori, url e metodo HTTP all'interno
// e gestisce tutta la richiesta, e testa la risposta
// eslint-disable-next-line no-unused-vars
function Payload (url, httpMethod, params, previousAction, payloadString, expectedResult, payloadType) {
  // console.log('a', url, httpMethod, params)

  this.url = url
  this.httpMethod = httpMethod
  this.params = params
  this.previousAction = previousAction
  this.payloadString = payloadString
  this.expectedResult = expectedResult
  this.payloadType = payloadType

  // console.log('b', this.params)
  // console.log('c', this.originalParams)

  this.request = async function () {
    const promises = []
    // console.log('for loop')
    for (let i = 0; i < this.params.length; i++) {
      promises.push(new Promise((resolve, reject) => {
        // fa il giro di tutti i parametri (nel test 2)
        // si copia i parametri originali, e SOLO nell'indice in cui si trova assegna il payload al parametro

        const modParams = JSON.parse(JSON.stringify(this.params))
        modParams[i][1] += payloadString

        // console.log(Object.fromEntries(modParams))

        // eslint-disable-next-line no-undef
        $.ajax(this.url, {
          type: this.httpMethod,
          data: Object.fromEntries(modParams)
        }).done((data) => {
          // console.log('d', data)
          // console.log('d', this.params, modParams, modParams[i][0], modParams[i][1], this.expectedResult, data)
          // eslint-disable-next-line no-eval
          eval(this.previousAction)
          // eslint-disable-next-line no-eval
          if (eval(this.expectedResult) === true) {
            // console.log('E', true)
            resolve({ return: true, url: this.url, httpMethod: this.httpMethod, paramName: modParams[i][0], paramValue: modParams[i][1], payloadType: this.payloadType })
          } else {
            // console.log('E', false)
            resolve({ return: false })
          }
        }).fail(() => {
          // console.log('E', false)
          resolve({ return: false })
        })
      })
      )
    }

    // if there is at least one true it means that the payload was successful
    return Promise.allSettled(promises).then((v) => {
      // eslint-disable-next-line array-callback-return
      const a = v.filter((v) => {
        if (v.value.return === true) { return v.value }
      })

      // console.log(a)
      if (a.length > 0) {
        return a[0].value
      } else {
        return false
      }
    })
  }

  this.isValidResponse = async function () {
    const response = await this.request()
    return response
  }
}

/* esempio:
console.log(new Payload(
  url,
  method,
  params,
  '1" && echo lalalaTEST_RCElalala #',
  // eslint-disable-next-line no-useless-escape
  "(data.indexOf('lalalaTEST_RCElalala') !== -1 && data.indexOf('echo lalalaTEST_RCElalala') === -1)",
  'RCE'
).isValidResponse()) */
