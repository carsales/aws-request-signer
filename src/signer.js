'use strict';

var algorithm = 'AWS4-HMAC-SHA256';
var hashedPayloads = new Array();

var enabled = false;
var region = '';
var service = '';
var accesskeyid = '';
var secretaccesskey = '';
var securitytoken = '';
var credentialtype_instanceprofile = false;
var credentialtype_explicit = false;

var instanceprofilecredentialscached = false;
var instanceprofilecredentialsexpiry;

function getsettings() {
	chrome.storage.sync.get({
		enabled: true,
		region: 'ap-southeast-2',
		service: 'es',
		accesskeyid: '',
		secretaccesskey: '',
		securitytoken: '',
		credentialtype_instanceprofile: true,
		credentialtype_explicit: false
		}, function(items) {
			enabled = items.enabled;
			region = items.region;
			service = items.service;
			accesskeyid = items.accesskeyid;
			secretaccesskey = items.secretaccesskey;
			securitytoken = items.securitytoken;
			credentialtype_instanceprofile = items.credentialtype_instanceprofile;
			credentialtype_explicit = items.credentialtype_explicit;
			
			updateicon();
			if (credentialtype_instanceprofile)
				getinstanceprofilecredentials();
	});
}

chrome.storage.onChanged.addListener(function(changes, namespace) {
	if (namespace !== 'sync')
		return;
	  
	  getsettings();
});

function updateicon() {
	if (enabled)
		chrome.browserAction.setIcon({path:'icon.png'});
	else
		chrome.browserAction.setIcon({path:'icon-off.png'});
}

chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
	  if (!enabled || !valid())
		  return;

	  var hashedPayload = getHashedPayload(details);
	  hashedPayloads[details.requestId] = hashedPayload;
	  log('Hashed Payload: ' + hashedPayload);
	  
	  return;
  },
  { urls: ["*://*.amazonaws.com/*"],
	types: ["main_frame","sub_frame","stylesheet","script","image","object","xmlhttprequest","other"]},
  ["blocking","requestBody"]
);

chrome.webRequest.onBeforeSendHeaders.addListener(
  function(details) {
	  if (!enabled || !valid())
		  return;
 
	  var authedHeaders = signRequest(details);
	  delete hashedPayloads[details.requestId];
 
	  return {requestHeaders: authedHeaders};
  },
  { urls: ["*://*.amazonaws.com/*"],
	types: ["main_frame","sub_frame","stylesheet","script","image","object","xmlhttprequest","other"]},
  ["blocking","requestHeaders"]
);

function valid() {
  if (!region || region.length === 0)
	  return false;
  if (!service || service.length === 0)
	  return false;
  if (!accesskeyid || accesskeyid.length === 0)
	  return false;
  if (!secretaccesskey || secretaccesskey.length === 0)
	  return false;
  if (!securitytoken || securitytoken.length === 0)
	  return false;
  
  return true;
}

function getinstanceprofilecredentials() {
  log('instance profile credential check');
  
  if (!enabled || !credentialtype_instanceprofile)
	  return;

  setTimeout(function() {getinstanceprofilecredentials();}, 60000);

  if (instanceprofilecredentialscached && instanceprofilecredentialsexpiry > new Date())
	  return;
  
  var profileurl = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';
  var x = new XMLHttpRequest();
  x.open('GET', profileurl);
  x.onerror = function() { log('error calling instance profile service'); };
  x.onload = function() {
    if (x.response) {
		var roles = x.response.split('<br/>');
		if (roles.length > 0) {
			var role = roles[0];
			
			var xx = new XMLHttpRequest();
			xx.responseType = 'json';
			xx.open('GET', profileurl + role);
			xx.onload = function () {
				if (xx.response) {
					var data = xx.response;
					if (data.Code === 'Success') {
						accesskeyid = data.AccessKeyId;
						secretaccesskey = data.SecretAccessKey;
						securitytoken = data.Token;
						instanceprofilecredentialsexpiry = new Date(data.Expiration);
						instanceprofilecredentialscached = true;
					}
				}
			}
			xx.send();
		}
    }

  };
  try {
	x.send();
  }
  catch (err) {
	log('could not reach instance profile service: ' + err);
  }
}

function signRequest(request) {
  log('Region: ' + region);
  log('Service: ' + service);
  log('Access Key Id: ' + accesskeyid);
  log('Secret Access Key: ' + secretaccesskey);
  log('Security Token: ' + securitytoken);

  var amzDateTime = getAmzDateTime();
  log('AmzDateTime: ' + amzDateTime);

  var amzDate = amzDateTime.substr(0,8);
  var headers = request.requestHeaders;
  headers.push({name:'X-Amz-Algorithm', value:algorithm});
  headers.push({name:'X-Amz-Date', value:amzDateTime});

  var url = request.url;
  var host = getHost(url);
  log('Host: ' + host);
  
  headers.push({name:'Host', value:host});
  
  var canonicalRequest = getCanonicalRequest(request);
  log('Canonical Request: ' + canonicalRequest);
  
  var canonicalRequestHash = CryptoJS.SHA256(canonicalRequest); 
  log('Canonical Request Hash: ' + canonicalRequestHash);
  
  var stringToSign = algorithm + '\n';
  stringToSign += amzDateTime + '\n';
  stringToSign += amzDate + '/' + region + '/' + service + '/' + 'aws4_request' + '\n';
  stringToSign += canonicalRequestHash;
  log('String To Sign: ' + stringToSign);
  
  var kDate = CryptoJS.HmacSHA256(amzDate, 'AWS4' + secretaccesskey);
  var kRegion = CryptoJS.HmacSHA256(region, kDate);
  var kService = CryptoJS.HmacSHA256(service, kRegion);
  var kKey = CryptoJS.HmacSHA256('aws4_request', kService);
  var signature = CryptoJS.HmacSHA256(stringToSign, kKey);
  log('Signature: ' + signature);
  
  var authorization = algorithm + ' ';
  authorization += 'Credential=' + accesskeyid + '/' + amzDate + '/' + region + '/' + service + '/' + 'aws4_request, ';
  authorization += 'SignedHeaders=' + getSignedHeaders(headers) + ', ';
  authorization += 'Signature=' + signature;
  log('Authorization: ' + authorization);

  headers.push({name:'Authorization', value:authorization});
  if (securitytoken)
	  headers.push({name:'X-Amz-Security-Token', value:securitytoken});
  
  return headers;
}

function getHost(url) {
  var parser = document.createElement('a');
  parser.href = url;
  var host = parser.hostname.toLowerCase();
  return host;
}
function getAmzDateTime() {
  var date = new Date();
  var amzDateTime = date.toISOString().replace(/[:\-]|\.\d{3}/g, '');
  return amzDateTime;
}
function getCanonicalRequest(request) {
  var url = request.url;
  var host = getHost(url);
  var method = request.method;
  var headers = request.requestHeaders;

  log('Url: ' + url);
  log('Host: ' + host);
  log('Method: ' + method);

  var canonicalUri = getCanonicalUri(url);
  var canonicalQuerystring = getCanonicalQueryString(url);
  var canonicalHeaders = getCanonicalHeaders(headers);
  var signedHeaders = getSignedHeaders(headers);
  
  log('Canonical URI: ' + canonicalUri);
  log('Canonical Querystring: ' + canonicalQuerystring);
  log('Canonical Headers: ' + canonicalHeaders);
  log('Signed Headers: ' + signedHeaders);
  
  var canonicalRequest = method + '\n';
  canonicalRequest += canonicalUri + '\n';
  canonicalRequest += canonicalQuerystring + '\n';
  canonicalRequest += canonicalHeaders + '\n';
  canonicalRequest += signedHeaders + '\n';
  canonicalRequest += hashedPayloads[request.requestId];
  
  return canonicalRequest;
}
function getCanonicalUri(url) {
  var parser = document.createElement('a');
  parser.href = url;
  var uri = parser.pathname;
  if (uri.length === 0)
	  uri = '/';
  else if (uri.substr(0,1) !== '/')
	  uri = '/' + uri;
  
  // aws wants asterisk encoded
  uri = uri.replace(/\*/g, '%2A');
  return uri;
}
function getCanonicalQueryString(url) {
  var parser = document.createElement('a');
  parser.href = url;
  var querystring = parser.search;
  var params = querystring.split('&');
  for (var i=0; i<params.length; i++) {
	  if (params[i].substr(0,1) === '?')
        params[i] = params[i].substr(1, params[i].length-1);
  }

  var sortedParams = params.sort();
  var canonicalQuerystring = sortedParams.join('&');
  return canonicalQuerystring;
}
function getCanonicalHeaders(headers) {
  var aggregatedHeaders = new Array();
  for (var i=0; i<headers.length; i++) {
	var name = headers[i].name.toLowerCase();
	
	if (name.indexOf('x-devtools-') > -1)
		continue;
	
	var headerfound = false;
	for (var x=0; x<aggregatedHeaders.length; x++) {
	  if (aggregatedHeaders[x].substr(0,name.length) === name) {
	    aggregatedHeaders[x] += headers[i].value.trim();
		headerfound=true;
	    break;
	  }
	}
	
	if (!headerfound)
		aggregatedHeaders.push(name + ':' + headers[i].value);
  }
  var sortedHeaders = aggregatedHeaders.sort(function(a,b) { 
    var name1 = a.substr(0,a.indexOf(':'));
	var name2 = b.substr(0,b.indexOf(':'));
    return name1 > name2;
  });
  var canonicalHeaders = sortedHeaders.join('\n');
  return canonicalHeaders + '\n';
}
function getSignedHeaders(headers) {
  var signedHeaders = new Array();
  for (var i=0; i<headers.length; i++) {
	var name = headers[i].name.toLowerCase();
	if (name.indexOf('x-devtools-') > -1)
		continue;
	signedHeaders.push(name);
  }
  var sortedHeaders = signedHeaders.sort();
  return sortedHeaders.join(';');
}
function getHashedPayload(request) {
  var body = request.requestBody;
  if (body && body.raw && body.raw.length > 0 && body.raw[0].bytes) {
	var str = String.fromCharCode.apply(String, new Uint8Array(body.raw[0].bytes));
	log('Raw Payload: ' + str);
	return CryptoJS.SHA256(str);
  }

  return CryptoJS.SHA256('');
}
function log(msg) {
  console.log( msg);
}

getsettings();