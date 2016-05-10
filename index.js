'use strict';

const createVerify = require('crypto').createVerify;
const isFunction = fn => 'function' === typeof fn && fn.constructor.name === 'Function'
const isStringLike = s => 'string' === typeof s || s instanceof Buffer
const getRawBody = require('raw-body');

module.exports = function(options) {
    options = Object.assign({
        key: null,
        algorithm: 'RSA-SHA1',
        format: 'base64',
		signature: 'signature'
    }, options);

	if (options.key && isStringLike(options.key)) {
		let key = options.key;
		options.key = function () {
			return key;
		};
	}
	if (!isFunction(options.key)) {
		throw new TypeError('Invalid options.key');
	}

	if (options.signature && isStringLike(options.signature)) {
		let header = options.signature.toLowerCase();
		options.signature = function (req) {
			return req.headers[header];
		};
	}

	if (!isFunction(options.signature)) {
		throw new TypeError('Invalid options.signature');
	}

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
        let key = options.key(this.request);
        this.assert(key != null, 400, 'No key');
        const verifier = createVerify(options.algorithm);
        verifier.end(body);
		let signature = options.signature(this.request);
        this.assert(signature, 400, 'No signature');
        const ok = verifier.verify(key, signature, options.format);
        this.assert(ok, 400, 'Could not verify receipt');
        yield next;
    };
};
