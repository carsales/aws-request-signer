'use strict';

var iconNum = 0;

function save_options() {
  var enabled = document.getElementById('enabled').checked;
  var region = document.getElementById('region').value;
  var service = document.getElementById('service').value;
  var accesskeyid = document.getElementById('accesskeyid').value;
  var secretaccesskey = document.getElementById('secretaccesskey').value;
  var securitytoken = document.getElementById('securitytoken').value;
  var credentialtype_instanceprofile = document.getElementById('credentialtype_instanceprofile').checked;
  var credentialtype_explicit = document.getElementById('credentialtype_explicit').checked;

  chrome.storage.sync.set({
	enabled: enabled,
    region: region,
	service: service,
	accesskeyid: accesskeyid,
	secretaccesskey: secretaccesskey,
	securitytoken: securitytoken,
	credentialtype_instanceprofile: credentialtype_instanceprofile,
	credentialtype_explicit: credentialtype_explicit
  }, function() {
    var status = document.getElementById('status');
    status.textContent = 'Options saved.';
    setTimeout(function() {
      status.textContent = '';
    }, 1000);
  });
}

function restore_options() {
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
	document.getElementById('enabled').checked = items.enabled;
	document.getElementById('region').value = items.region;
	document.getElementById('service').value = items.service;
	document.getElementById('accesskeyid').value = items.accesskeyid;
	document.getElementById('secretaccesskey').value = items.secretaccesskey;
	document.getElementById('securitytoken').value = items.securitytoken;
	document.getElementById('credentialtype_instanceprofile').checked = items.credentialtype_instanceprofile;
	document.getElementById('credentialtype_explicit').checked = items.credentialtype_explicit;
	toggle_credential_inputs(items.credentialtype_instanceprofile);
  });
}
function toggle_credential_inputs(instanceprofile) {
	document.getElementById('accesskeyid').disabled = instanceprofile;
	document.getElementById('secretaccesskey').disabled = instanceprofile;
	document.getElementById('securitytoken').disabled = instanceprofile;
}
function toggle_settings(enabled) {
	document.getElementById('region').disabled = !enabled;
	document.getElementById('service').disabled = !enabled;
	document.getElementById('credentialtype_instanceprofile').disabled = !enabled;
	document.getElementById('credentialtype_explicit').disabled = !enabled;
	if (!enabled)
		toggle_credential_inputs(true);
	else
		toggle_credential_inputs(document.getElementById('credentialtype_instanceprofile').checked);
}

document.addEventListener('DOMContentLoaded', restore_options);
document.getElementById('credentialtype_instanceprofile').addEventListener('click', function(e) {
	toggle_credential_inputs(true);
});
document.getElementById('credentialtype_explicit').addEventListener('click', function(e) {
	toggle_credential_inputs(false);
});
document.getElementById('enabled').addEventListener('click', function(e) {
	toggle_settings(e.srcElement.checked);
});
document.getElementById('save').addEventListener('click', save_options);

window.setInterval(function(){ 
	document.getElementById('icon').src = 'icon-' + (iconNum++) + '.png';
	if (iconNum > 2)
		iconNum = 0;
}, 1000);
