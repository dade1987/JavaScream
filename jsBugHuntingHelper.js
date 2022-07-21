// Created by Davide Cavallini
// linkedin: https://www.linkedin.com/in/davidecavallini/

// This tool is studied to help Ethical Hackers to find vulnerable points in webpage's javascript
// Just open the webpage, select all this code, copy and past in browser's console

// eslint-disable-next-line prefer-const, no-var
var alreadyProcessedFunctions = []

function getAllIndexes (arr, val) {
  const indexes = []; let i = -1
  while ((i = arr.indexOf(val, i + 1)) !== -1) {
    indexes.push(i)
  }
  return indexes
}

function recursiveEnumerate (object, level, previousPath) {
  const searchElements = [/*'/*', '//', */'"POST"', '"GET"', "'POST", "'GET'", '.ajax(', '.post(', 'query', '/api', '.php', 'mysql', 'email', 'username', 'password']

  level++
  const objKeys = Object.keys(object)
  for (let o = 0; o < objKeys.length; o++) {
    if (object[objKeys[o]] !== null && alreadyProcessedFunctions.indexOf(objKeys[o]) === -1 && (typeof object[objKeys[o]] === 'function' || typeof object[objKeys[o]] === 'object') && objKeys[o] !== 'recursiveEnumerate') {
      alreadyProcessedFunctions.push(objKeys[o])
      try {
        const functionToString = object[objKeys[o]].toString().replace(/(\r\n|\n|\r)/gm, '').replace(/\s\s+/g, ' ')
        searchElements.forEach((v) => {
          const index = getAllIndexes(functionToString, v)
          index.forEach((ind) => {
            console.log(level, objKeys[o], object[objKeys[o]], functionToString.substr(ind - 20, 50))
          })
        })
        if (level < 5 && objKeys[o] !== 'set' && objKeys[o] !== 'push') {
          recursiveEnumerate(object[objKeys[o]], level)
        }
      } catch (e) {

      }
    }
  }
}

console.log('Created by Davide Cavallini')
console.log('Linkedin: https://www.linkedin.com/in/davidecavallini/')
console.log('----------------------------------------------------------')
console.log('\n')

recursiveEnumerate(window, 0)

console.log('\n')
console.log('----------------------------------------------------------')
console.log('Created by Davide Cavallini')
console.log('Linkedin: https://www.linkedin.com/in/davidecavallini/')