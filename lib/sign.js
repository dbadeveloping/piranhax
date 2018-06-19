const url = require("url")
const querystring = require("querystring")
const jsrasign = require("jsrasign")

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
        const header = { alg: 'HS256' };
        return Promise.resolve(
            jws.JWS.sign(
                null,
                JSON.stringify(header),
                JSON.stringify(payload),
                { utf8: secret }
            )
        );
    }

    /**
     * Calculate SHA-256 of HMAC with base64 encoding.
     * @return {string} base64 string from HMAC digest
     */
    calculate() {
        // create hmac
        //crypto.createHmac("sha256", this.secret)
        const hmac = this.generateHMAC(this.stringToSign, this.secret) 
    
        // update data to hmac
        // hmac.update(this.stringToSign)

        // digest it
        // return hmac.digest("base64")
        return hmac
    }
}

// exports Sign class
module.exports = Sign
