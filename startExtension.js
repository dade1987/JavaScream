// eslint-disable-next-line no-unused-expressions
(function () {
  // Create a button element
  const button = document.createElement('button')

  // Set the button text to 'Can you click me?'
  button.innerText = 'SCAN PAGE'

  button.style.position = 'fixed'
  button.style.bottom = '100px'
  button.style.right = '200px'
  button.style.backgroundColor = 'black'
  button.style.borderRadius = '5px'
  button.style.padding = '20px'
  button.style.fontSize = '20px'
  button.style.color = 'white'

  button.addEventListener('click', () => {
    // eslint-disable-next-line no-undef
    jBHH.init()
  })

  document.body.appendChild(button)
})()
