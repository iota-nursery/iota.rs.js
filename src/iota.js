"use strict";

import * as Module from "./iota-rs.js"

// fn curl_pair_new() -> *Curl 
const curl_pair_new = Module.cwrap('curl_pair_new', 'number', [])
// fn curl_pair_delete(*Curl)
const curl_pair_delete = Module.cwrap('curl_pair_delete', '', ['number'])
// fn curl_pair_absorb(*Curl, Trinary) -> digest
const curl_pair_absorb = Module.cwrap('curl_pair_absorb', '', ['number', 'string'])
// fn curl_pair_reset(*Curl)
const curl_pair_reset = Module.cwrap('curl_pair_reset', '', ['number'])
// fn curl_pair_squeeze(*Curl, trit_count) -> signature
const curl_pair_squeeze = Module.cwrap('curl_pair_squeeze', 'string', ['number', 'number'])

// fn curl_simple_new() -> *Curl 
const curl_simple_new = Module.cwrap('curl_simple_new', 'number', [])
// fn curl_simple_delete(*Curl)
const curl_simple_delete = Module.cwrap('curl_simple_delete', '', ['number'])
// fn curl_simple_absorb(*Curl, Trinary) -> digest
const curl_simple_absorb = Module.cwrap('curl_simple_absorb', '', ['number', 'string'])
// fn curl_simple_reset(*Curl)
const curl_simple_reset = Module.cwrap('curl_simple_reset', '', ['number'])
// fn curl_simple_squeeze(*Curl, trit_count) -> signature
const curl_simple_squeeze = Module.cwrap('curl_simple_squeeze', 'string', ['number', 'number'])

const curl = Symbol("curl")
const pair = Symbol("pair")
const deleted = Symbol("deleted");

class Curl {
    constructor(pair) {
        this[deleted] = false;
        if (pair) {
            this[curl] = curl_pair_new()
            this[pair] = true
        } else {
            this[curl] = curl_simple_new()
        }
    }
    check_deleted() {
        if (this[deleted]) throw "Curl: use-after-free";
    }
    absorb(trinary) {
        this.check_deleted();
        if (this[pair]) {
            curl_pair_absorb(this[curl], trinary)
        } else {
            curl_simple_absorb(this[curl], trinary)
        }
    }
    squeeze(size) {
        this.check_deleted();
        if (this[pair]) {
            return curl_pair_squeeze(this[curl], size)
        } else {
            return curl_simple_squeeze(this[curl], size)
        }
    }
    reset() {
        this.check_deleted();
        if (this[pair]) {
            curl_pair_reset(this[curl])
        } else {
            curl_simple_reset(this[curl])
        }
    }
    destroy() {
        if (this[pair]) {
            curl_pair_delete(this[curl])
        } else {
            curl_simple_delete(this[curl])
        }
        this[deleted] = true;
    }
}

export default Curl;
