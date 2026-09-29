'use strict';

/**
 * Regression tests for the fixes carried by the tonmat-node-firebird fork on
 * top of upstream node-firebird. Kept in their own file (with a small copy of
 * the mock-server harness) so rebasing the fork onto a new upstream release
 * only touches the vitest include list.
 *
 * Most tests speak the wire protocol against an in-process mock server; the
 * "real server" block needs the Firebird instance the rest of the suite uses.
 */

const net    = require('net');
const assert = require('assert');

const Const    = require('../lib/wire/const');
const {XdrWriter, BlrWriter} = require('../lib/wire/serialize');
const srp      = require('../lib/srp');
const Firebird = require('../lib');
const Config   = require('./config');

const SRP_TEST_USER     = 'SYSDBA';
const SRP_TEST_PASSWORD = 'masterkey';
const SRP_TEST_SALT     = 'a8ae6e6ee929abea3afcfc5258c8ccd6f85273e0d4626d26c7279f3250f77c8e';

// ---------------------------------------------------------------------------
// Mock-server harness (subset of test/mock-server.js)
// ---------------------------------------------------------------------------

function startMockServer(onClient) {
    return new Promise((resolve, reject) => {
        const server = net.createServer(onClient);
        server.on('error', reject);
        server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
    });
}

function stopMockServer(server) {
    return new Promise(resolve => server.close(resolve));
}

/** Passes the accumulated buffer to handler(socket, opcode, buf); on loopback
 *  every client write is one logical message, so handlers consume it all. */
function makeFullDispatcher(socket, handler) {
    let buf = Buffer.alloc(0);
    socket.on('data', chunk => {
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 4) {
            const consumed = handler(socket, buf.readInt32BE(0), buf);
            if (consumed <= 0) break;
            buf = buf.slice(consumed);
        }
    });
}

function buildOpAcceptData() {
    const w = new XdrWriter(128);
    w.addInt(Const.op_accept_data);
    w.addInt(Const.PROTOCOL_VERSION14);
    w.addInt(Const.ARCHITECTURE_GENERIC);
    w.addInt(Const.ptype_lazy_send);
    w.addInt(0);                    // auth data array len=0
    w.addString('Legacy_Auth', 'utf8');
    w.addInt(1);                    // is_authenticated=1
    w.addString('', 'utf8');        // keys=""
    return w.getData();
}

function buildOpResponse(handle) {
    const w = new XdrWriter(32);
    w.addInt(Const.op_response);
    w.addInt(handle);
    w.addInt(0); w.addInt(0);       // oid
    w.addInt(0);                    // data array length = 0
    w.addInt(Const.isc_arg_end);
    return w.getData();
}

/** op_response carrying a failure status vector: gdscode + string args. */
function buildOpResponseError(gdscode, ...args) {
    const w = new XdrWriter(256);
    w.addInt(Const.op_response);
    w.addInt(0);                    // handle
    w.addInt(0); w.addInt(0);       // oid
    w.addInt(0);                    // data array length = 0
    w.addInt(Const.isc_arg_gds);
    w.addInt(gdscode);
    for (const arg of args) {
        w.addInt(Const.isc_arg_string);
        w.addString(arg, 'utf8');
    }
    w.addInt(Const.isc_arg_end);
    return w.getData();
}

/** op_cond_accept with an EMPTY auth-data array: the client must (re)send
 *  its public key A via op_cont_auth. */
function buildOpCondAcceptSrpEmpty(protocolVersion) {
    const w = new XdrWriter(64);
    w.addInt(Const.op_cond_accept);
    w.addInt(protocolVersion);
    w.addInt(Const.ARCHITECTURE_GENERIC);
    w.addInt(Const.ptype_lazy_send);
    w.addInt(0);                    // auth data array len = 0
    w.addString('Srp', 'utf8');
    w.addInt(0);                    // is_authenticated = 0
    w.addString('', 'utf8');        // keys = ""
    return w.getData();
}

/** Server op_cont_auth with no data (empty array) — or an M2 proof. */
function buildOpContAuthEmpty() {
    const w = new XdrWriter(64);
    w.addInt(Const.op_cont_auth);
    w.addInt(0);                    // empty data array
    w.addString('Srp', 'utf8');
    w.addString('', 'utf8');        // plist
    w.addString('', 'utf8');        // pkey
    return w.getData();
}

/** Server op_cont_auth carrying salt + B; keyHex overrides B so tests can
 *  inject malformed (non-hex) key data. */
function buildOpContAuthSalt(salt, serverB, keyHex) {
    const bHex = keyHex !== undefined ? keyHex : srp.hexPad(serverB.toString(16));
    const authBlr = new BlrWriter(4 + salt.length + 4 + bHex.length);
    authBlr.addWord(salt.length);
    authBlr.ensure(salt.length);
    authBlr.buffer.write(salt, authBlr.pos, 'utf8');
    authBlr.pos += salt.length;
    authBlr.addWord(bHex.length);
    authBlr.ensure(bHex.length);
    authBlr.buffer.write(bHex, authBlr.pos, 'utf8');
    authBlr.pos += bHex.length;

    const w = new XdrWriter(128 + authBlr.pos);
    w.addInt(Const.op_cont_auth);
    w.addBlr(authBlr);
    w.addString('Srp', 'utf8');
    w.addString('', 'utf8');        // plist
    w.addString('', 'utf8');        // pkey
    return w.getData();
}

function buildOpAccept(protocolVersion) {
    const w = new XdrWriter(16);
    w.addInt(Const.op_accept);
    w.addInt(protocolVersion);
    w.addInt(Const.ARCHITECTURE_GENERIC);
    w.addInt(Const.ptype_lazy_send);
    return w.getData();
}

const MOCK_OPTIONS = {
    host: '127.0.0.1',
    database: '/mock/test.fdb',
    user: SRP_TEST_USER,
    password: SRP_TEST_PASSWORD,
};

function attachAsync(options) {
    return new Promise((resolve, reject) => {
        Firebird.attach(options, (err, db) => (err ? reject(err) : resolve(db)));
    });
}

function withMockSrpAttach(port) {
    return attachAsync(Object.assign({}, MOCK_OPTIONS, {
        port,
        pluginName: Const.AUTH_PLUGIN_SRP,
        wireCrypt: Const.WIRE_CRYPT_DISABLE,
    }));
}

/** Resolves when the server side sees the client close its socket. */
function whenClientCloses(socket, timeoutMs) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(
            () => reject(new Error('client kept the socket open for ' + timeoutMs + 'ms')),
            timeoutMs);
        socket.once('close', () => {
            clearTimeout(timer);
            resolve();
        });
    });
}

// ---------------------------------------------------------------------------
// Default isolation (fork 2.3.4-c)
// ---------------------------------------------------------------------------

describe('tonmat fork – default READ COMMITTED isolation', function () {

    it('should use rec_version so readers never block behind uncommitted writers', function () {
        assert.deepStrictEqual(Firebird.ISOLATION_READ_COMMITTED,
            [Const.isc_tpb_read_committed, Const.isc_tpb_rec_version]);
    });

    it('should keep the blocking no_rec_version variant available by name', function () {
        assert.deepStrictEqual(Firebird.ISOLATION_READ_COMMITTED_NO_REC_VERSION,
            [Const.isc_tpb_read_committed, Const.isc_tpb_no_rec_version]);
    });
});
