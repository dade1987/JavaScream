const b = 'mmmnns'

const ar = {
  m: 'abc',
  n: '123',
  s: '!$%'
}

let pass = ''

const c = [...b]

c.forEach((v) => {
  pass += ar[v][0]
})

// eslint-disable-next-line no-extend-native
String.prototype.replaceAt = function (index, replacement) {
  return this.substring(0, index) + replacement + this.substring(index + replacement.length)
}

function r (p, index) {
  for (let i = 0; i < p.length; i++) {
    const d = [...ar[p[0]]]

    // console.log(d)

    d.forEach((v) => {
      pass = pass.replaceAt(index, v)
      console.log(pass)
    })

    p = p.slice(1)
    index++

    if (p.length > 0) {
      r(p, index)
    }
  }
}

r(b, 0)
