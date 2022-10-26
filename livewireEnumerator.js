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


//https://master--goofy-tereshkova-ff1e2b.netlify.app/docs/alpine-js/
livewire.find('wzDaqpljO7XDn08cla1b').get('title')

livewire.find('wzDaqpljO7XDn08cla1b').set('title', 'test')

//reference https://laravel-livewire.com/docs/2.x/reference


Object.values(Livewire.components.componentsById).forEach(function(v) {
    try {
        console.log(v.id, v.listeners, v.serverMemo.data, v.serverMemo.dataMeta.models /*, v.lastFreshHtml*/ )
        console.log(Livewire.find(v.id).get('id'))
    } catch (e) {

    }
})


Object.values(Livewire.components.componentsById).forEach(function(v) {
    try {
        console.log(v.id, v.listeners, v.serverMemo.data, v.serverMemo.dataMeta.models /*, v.lastFreshHtml*/ )

        Object.keys(v.serverMemo.data).forEach((k) => {
            console.log(k, Livewire.find(v.id).get(k))
        })
    } catch (e) {}
})

//livewire.find('id').set() e livewire.find('id').get()