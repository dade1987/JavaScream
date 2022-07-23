# jsBugHuntingHelper
This tool is studied to help ethical hackers to find vulnerable points in webpage's javascript.


ONLY IN CHROME AND EDGE YOU CAN

1- open console
2- copy and paste this code in the address bar (there could be cache problems with CDN)
```
javascript:(function () { var a = document.createElement('script'); a.src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"; document.body.appendChild(a); a.onload = function () { var b = document.createElement('script'); b.src="//cdn.jsdelivr.net/gh/dade1987/jsBugHuntingHelper/jsBugHuntingHelper.min.js"; document.body.appendChild(b); b.onload = function () { jBHH.init() } } })();
```

IN FIREFOX AND TOR BROWSER


1- open console
2- copy this code
```
!function(){function b(){console.log("jQuery loaded");let a=document.createElement("script");a.src="//cdn.jsdelivr.net/gh/dade1987/jsBugHuntingHelper/jsBugHuntingHelper.min.js",document.body.appendChild(a),a.onload=function(){jBHH.init()}}if(window.jQuery)b();else{let a=document.createElement("script");a.src="//cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js",document.body.appendChild(a),a.onload=function(){b()}}}();
```

BEST METHOD (BECAUSE CDN CACHE MAY HAVE AN OLD VERSION)

1- open the webpage

2- if jQuery is missing, copy this in the browser console
```
if(!window.jQuery){let a=document.createElement("script");a.src="//cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js",document.body.appendChild(a),a.onload=function(){console.log("jQuery Loaded")}}
```
3- copy all the code in https://raw.githubusercontent.com/dade1987/jsBugHuntingHelper/main/jsBugHuntingHelper.min.js in browser console.
4- type this in console
```
jBHH.init()
```

Created by Davide Cavallini - Linkedin: https://www.linkedin.com/in/davidecavallini/