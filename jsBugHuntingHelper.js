// Created by Davide Cavallini
// linkedin: https://www.linkedin.com/in/davidecavallini/

// This tool is studied to help Ethical Hackers to find vulnerable points in webpage's javascript
// Just open the webpage, select all this code, copy and past in browser's console

'use strict'


var alreadyProcessedFunctions = []

function SearchElement(description, type, string) {
  this.description = description;
  this.type = type;
  this.string = string;
}

// eslint-disable-next-line prefer-const, no-var
var searchElements = [
  new SearchElement('form', 'string', '<form'),
  new SearchElement('url', 'string', 'http://'),
  new SearchElement('url', 'string', 'https://'),
  new SearchElement('web socket', 'string', 'ws://'),
  new SearchElement('web socket', 'string', 'wss://'),
  new SearchElement('single line comment', 'string', ' //'),
  new SearchElement('block comment', 'string', '/*'),
  new SearchElement('post request', 'string', '"POST"'),
  new SearchElement('get request', 'string', '"GET"'),
  new SearchElement('post request', 'string', "'POST"),
  new SearchElement('get request', 'string', "'GET'"),
  new SearchElement('ajax request', 'string', '.ajax('),
  new SearchElement('ajax post request', 'string', '.post('),
  new SearchElement('query', 'string', 'query'),
  new SearchElement('api call', 'string', '/api'),
  new SearchElement('php file', 'string', '.php'),
  new SearchElement('asp file', 'string', '.asp'),
  new SearchElement('json file', 'string', '.json'),
  new SearchElement('mailto protocol', 'string', 'mailto:'),
  new SearchElement('something on mysql', 'string', 'mysql'),
  new SearchElement('something on email', 'string', 'email'),
  new SearchElement('something on username', 'string', 'username'),
  new SearchElement('something on username', 'string', 'user'),
  new SearchElement('something on password', 'string', 'password'),
  new SearchElement('something on password', 'string', 'pass'),
  new SearchElement('something on password', 'string', 'psw'),
  new SearchElement('something on password', 'string', 'pwd')]
  new SearchElement('REGEX email address', 'regEx', /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
  new SearchElement('REGEX API Key', 'regEx', /^[a-f0-9]{32}$/)

function regexIndexOf(string, regex, startpos) {
  var indexOf = string.substring(startpos || 0).search(regex);
  return (indexOf >= 0) ? (indexOf + (startpos || 0)) : indexOf;
}

function regexAllIndexOf(string, regex, startpos) {
  const indexes = [];

  regex = (regex.global) ? regex : new RegExp(regex.source, "g" + (regex.ignoreCase ? "i" : "") + (regex.multiLine ? "m" : ""));
  if(typeof (startpos) == "undefined") {
      startpos = string.length;
  } else if(startpos < 0) {
      startpos = 0;
  }
  var stringToWorkWith = string.substring(0, startpos + 1);
  var lastIndexOf = -1;
  var nextStop = 0;
  while((result = regex.exec(stringToWorkWith)) != null) {
      lastIndexOf = result.index;
      regex.lastIndex = ++nextStop;
      indexes.push(lastIndexOf)
  }
  return lastIndexOf;
}

function getAllIndexes (arr, val) {
  const indexes = []; let i = -1
  while ((i = arr.indexOf(val, i + 1)) !== -1) {
    indexes.push(i)
  }
  return indexes
}

function searchInside (functionToString, object, objKeys, o, level) {
  if(objKeys[o] === undefined) {
    objKeys[o] = 'BODY'
  }
  if(object[objKeys[o]] === undefined) {
    object[objKeys[o]] = 'BODY'
  }
  
  searchElements.forEach((v) => {
    if(v.type === 'string') {
      const index = getAllIndexes(functionToString, v.string)
      index.forEach((ind) => {
        console.log('DDDX ' + v.description, level, objKeys[o], object[objKeys[o]], functionToString.substr(ind - 15, 60))
      })
    } else if(v.type === 'regEx'){
      const index =  regexAllIndexOf(functionToString, v.string, 0)
      index.forEach((ind) => {
        console.log('DDDX regEx ' + v.description, level, objKeys[o], object[objKeys[o]], functionToString.substr(ind - 15, 60))
      })
    }
  })
}

function recursiveEnumerate (object, level) {

  level++
  const objKeys = Object.keys(object)
  for (let o = 0; o < objKeys.length; o++) {
    if (object[objKeys[o]] !== null && alreadyProcessedFunctions.indexOf(objKeys[o]) === -1 && (typeof object[objKeys[o]] === 'function' || typeof object[objKeys[o]] === 'object') && objKeys[o] !== 'recursiveEnumerate' && objKeys[o] !== 'alreadyProcessedFunctions') {
      alreadyProcessedFunctions.push(objKeys[o])
      try {
        const functionToString = object[objKeys[o]].toString().replace(/(\r\n|\n|\r)/gm, '').replace(/\s\s+/g, ' ')
        searchInside(functionToString, object, objKeys, o, level)
        if (objKeys[o] !== 'set' && objKeys[o] !== 'push') {
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
searchInside(document.body.innerHTML.replace(/(\r\n|\n|\r)/gm, '').replace(/\s\s+/g, ' '), document.body, [], 0, 0)

console.log('\n')
console.log('----------------------------------------------------------')
console.log('Created by Davide Cavallini')
console.log('Linkedin: https://www.linkedin.com/in/davidecavallini/')