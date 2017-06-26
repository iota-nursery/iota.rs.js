var Module = require("../lib/iota-rs.js");

// fn subseed(seed, index) -> subseed
var iss_subseed = Module.cwrap('subseed', 'string', ['string', 'number']);
// fn key(subseed) -> key
var iss_key = Module.cwrap('key', 'string', ['string']);
// fn digest_key(key) -> digest
var iss_digest_key = Module.cwrap('digest_key', 'string', ['string']);
// fn address(digests) -> address 
var iss_address = Module.cwrap('address', 'string', ['string']);
// fn signature(bundle, key) -> signature
var iss_signature = Module.cwrap('signature', 'string', ['string', 'string']);
// fn digest_bundle_signature(bundle, key) -> signature
var iss_digest_bundle_signature = Module.cwrap('digest_bundle_signature', 'string', ['string', 'string']);

var seed = "WJRVZJOSSMRCGCJYFN9SSETWFLRCPWSCOEPPT9KNHWUTTW9BTELBWDPMHDRN9NTFGWESKAKZCFHGBJJQZ";
var subseed = iss_subseed(seed, 0);
console.log("Subseed: " + subseed);
var key = iss_key(subseed);
console.log("Key: " + key);
var key_digest = iss_digest_key(key);
console.log("Key digests: " + key_digest);
var address = iss_address(key_digest);
console.log("Address: " + address);
