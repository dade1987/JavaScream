// dentro la pagina

Object.values(Livewire.components.componentsById).forEach(function(v) {
    console.log(v)
})


//esempio:

Object.values(Livewire.components.componentsById).forEach(function(v) {
    console.log(v.effects, v.fingerprint, v.listeners, v.serverMemo, v.lastFreshHtml)
})


//oppure

Livewire.components.components()


let charset = {
    m: 'abc',
    n: 123,
    s: '!#$'
}

function bruteforce(pattern) {

    password = ''

    for (let i = 0; i < pattern.length; i++) {
        password += ' ';
    }

    r(pattern, pattern, password)

}

function r(internalPattern, pattern, password)

internalPattern = internalPattern.slice(0, -1)

for (let i = 0; i < charset[internalPattern[0]].length; i++) {

    password[pattern.length - internalPattern.length - 1] = internalCharset[c]

}

r(internalPattern, pattern, password)
}


requestAndCheck(url, params, expectedResponse, ecc)
    //ajax
}

pattern = 'mmnns';
bruteforce(pattern)