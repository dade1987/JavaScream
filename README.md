# jsBugHuntingHelper
This tool is studied to help ethical hackers to find vulnerable points in webpage's javascript.

Just open the webpage, select all the code in jsBugHuntingHelper.js, copy and past in browser's console.

OR

copy and paste it in the address bar

```
javascript:!function(){function b(){console.log("jQuery loaded");let a=document.createElement("script");a.src="//cdn.jsdelivr.net/gh/dade1987/jsBugHuntingHelper@main/jsBugHuntingHelper.min.js",document.body.appendChild(a),a.onload=function(){jBHH.init()}}if(window.jQuery)b();else{let a=document.createElement("script");a.src="//cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js",document.body.appendChild(a),a.onload=function(){b()}}}();
```

Created by Davide Cavallini - Linkedin: https://www.linkedin.com/in/davidecavallini/