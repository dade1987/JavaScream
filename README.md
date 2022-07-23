# jsBugHuntingHelper
This tool is studied to help ethical hackers to find vulnerable points in webpage's javascript.

Just open the webpage, select all the code in jsBugHuntingHelper.js, copy and past in browser's console.

OR

copy and paste it in the address bar

```
javascript:(function () { var script = document.createElement('script'); script.src="//cdn.jsdelivr.net/gh/dade1987/jsBugHuntingHelper@main/jsBugHuntingHelper.min.js"; document.body.appendChild(script); script.onload = function () { jBHH.init() } })();
```

Created by Davide Cavallini - Linkedin: https://www.linkedin.com/in/davidecavallini/