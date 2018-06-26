const Buffer = require('buffer/').Buffer;
const url = require("url");
const querystring = require("querystring");
var rs = require('jsrsasign');

// Sign implements hmac SHA-256 signing method to Amazon AWSECommerceService
class Sign {
    constructor(urlToSign, secret) {
        this.secret = secret
        this.urlObject = url.parse(urlToSign)
        this.sortedQuery = []

        this._split()
        this._sort()
        this._prepend()
    }

    // prepend sorted query with data
    _prepend() {
        this.stringToSign = "GET\n"
        this.stringToSign += this.urlObject.hostname + "\n"
        this.stringToSign += this.urlObject.pathname + "\n"
        this.stringToSign += this.sortedQuery.join("&")
    }

    // split query by &
    _split() {
        this.query = this.urlObject.query.split("&")
    }

    // sort by bytes
    _sort() {
        let bytes = []

        // sort bytes
        for (var x in this.query) {
            let buf = Buffer.from(this.query[x])
            bytes.push(buf)
        }
        bytes.sort(Buffer.compare)

        // convert back to string
        for (var b in bytes) {
            this.sortedQuery.push(bytes[b].toString())
        }
    }

    /**
     * Rejoin querystring
     * @return {Object} QueryString object
     */
    rejoinedQuery() {
        let sortedQuery = this.sortedQuery.join("&")
        return querystring.parse(sortedQuery)
    }

    generateHMAC(payload, secret) {
        const hmac_alg = new rs.KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"utf8": secret}});
        const hmac = hmac_alg.doFinalString(payload);
        return rs.hextob64(hmac);
    }

    /**
     * Calculate SHA-256 of HMAC with base64 encoding.
     * @return {string} base64 string from HMAC digest
     */
    calculate() {
        // create hmac
        const hmac_alg = new rs.KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"utf8": this.secret}});
        const hmac = hmac_alg.doFinalString(this.stringToSign);
        return rs.hextob64(hmac);
    }
}

// exports Sign class
module.exports = Sign
