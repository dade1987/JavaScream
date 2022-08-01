// eslint-disable-next-line no-unused-vars
function Mapper (initalFunctionName) {
  window.wrappedJSObject !== undefined ? this.originalWinObj = window.wrappedJSObject : this.originalWinObj = window

  const mapArray = []

  function init (functionName, level) {
    level++
    Object.entries(this.originalWinObj).forEach((v) => {
      if (typeof v[1] === 'function' && v[0] !== functionName && v[1].toString().indexOf(functionName) !== -1) {
        mapArray.push({ functionName: v[0], function: v[1], level })
        init(v[0], level)
      }
    })
  }

  init(initalFunctionName, 0)

  const result = mapArray

  console.log('Level:', 0, 'Function Name:', initalFunctionName)
  result.forEach((v) => {
    console.log('Level', v.level, 'Function Name:', v.functionName, 'Function:', v.function)
  })
}
