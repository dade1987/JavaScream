# jsBugHuntingHelper
This tool is studied to help ethical hackers to find vulnerable points in webpage's javascript.

1- open the webpage
2- if jQuery is missing, copy this in the browser console

```
if(!window.jQuery){let a=document.createElement("script");a.src="//cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js",document.body.appendChild(a),a.onload=function(){console.log("jQuery Loaded")}}
```

3- copy all the code in jsBugHuntingHelper.min.js in browser console.

OR

copy and paste this code in the address bar (there could be cache problems with CDN)


```
javascript:!function(){function b(){console.log("jQuery loaded");let a=document.createElement("script");a.src="//cdn.jsdelivr.net/gh/dade1987/jsBugHuntingHelper@main/jsBugHuntingHelper.min.js",document.body.appendChild(a),a.onload=function(){jBHH.init()}}if(window.jQuery)b();else{let a=document.createElement("script");a.src="//cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js",document.body.appendChild(a),a.onload=function(){b()}}}();
```

Created by Davide Cavallini - Linkedin: https://www.linkedin.com/in/davidecavallini/