'use strict';

const createVerify = require('crypto').createVerify;
const isFunction = fn => 'function' === typeof fn && fn.constructor.name === 'Function'
const getRawBody = require('raw-body');

module.exports = function(options) {
    options = Object.assign({
        key: null,
        algorithm: 'RSA-SHA1',
        format: 'base64'
    }, options);

    return function *verifyGoogleplayReceiptMiddleware(next) {
        const body = yield getRawBody(this.req, {
            size: this.size,
            encoding: this.encoding
        });
        try {
            this.request.body = body != null ? JSON.parse(`${body}`) : body;
        } catch (err) {
            this.throw(400, err.message);
        }
        let key = options.key;
        if (isFunction(key)) key = key.call(this, this.req);
        this.assert(key != null, 400, 'No key');
        const verifier = createVerify(options.algorithm);
        verifier.end(body);
        const signature = this.request.headers.signature;
        this.assert(signature, 400, 'No signature');
        const ok = verifier.verify(key, signature, options.format);
        this.assert(ok, 400, 'Could not verify receipt');
        yield next;
    };
};
