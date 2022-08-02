/* eslint-disable no-undef */
/* eslint-disable no-unused-vars */
function f01 () {
  const params = []
  $.get('test.php', params, {}).done((d) => {})
}

function f02 () {
  const url = 'https://url.url'
}

function f03 () {
  const params = []
  $.post('test.php', params, {}).done((d) => {})
}

function f04 () {
  /* this is a random comment
      multiline */
}

function f05 () {
  function reqListener () {
    console.log(this.responseText)
  }

  const oReq = new XMLHttpRequest()
  oReq.addEventListener('load', reqListener)
  oReq.open('GET', 'http://www.example.org/example.txt')
  oReq.send()
}

function f06 () {
  return true
}

function f07 () {
  function reqListener () {
    console.log(this.responseText)
  }

  const oReq = new XMLHttpRequest()
  oReq.addEventListener('load', reqListener)
  oReq.open('POST', 'http://www.example.org/example.txt')
  oReq.send()
}

function f08 () {
  console.log('ciao')
}

function f09 () {
  // ciao
}

function f10 () {
  console.table('ciao')
}
