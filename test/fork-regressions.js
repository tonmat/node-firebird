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

/** Record, from the moment the server accepts it, when the client closes
 *  the socket — the close may happen before the test starts waiting. */
function trackClose(socket) {
    socket.clientClosed = new Promise(resolve => socket.once('close', resolve));
    return socket;
}

/** Resolves when the server side sees the client close its socket. */
function whenClientCloses(socket, timeoutMs) {
    let timer;
    return Promise.race([
        socket.clientClosed.finally(() => clearTimeout(timer)),
        new Promise((resolve, reject) => {
            timer = setTimeout(
                () => reject(new Error('client kept the socket open for ' + timeoutMs + 'ms')),
                timeoutMs);
        }),
    ]);
}

// ---------------------------------------------------------------------------
// SRP handshake robustness (fork 2.3.4-b)
// ---------------------------------------------------------------------------

describe('tonmat fork – SRP handshake robustness', function () {

    /**
     * Production crash regression: the server answered the client public key
     * with op_cont_auth carrying an EMPTY data array (no salt+key yet), which
     * used to kill the process with an uncaughtException. The client must
     * restart the handshake by re-sending its public key, then complete auth
     * once the server delivers salt+B.
     */
    it('should restart the SRP handshake when the server sends op_cont_auth with empty data', async function () {
        const protocolVersion = Const.PROTOCOL_VERSION16;
        const serverKeys = srp.serverSeed(SRP_TEST_USER, SRP_TEST_PASSWORD, SRP_TEST_SALT);
        let contAuthCount = 0;

        const { server, port } = await startMockServer(socket => {
            makeFullDispatcher(socket, (s, opcode, buf) => {
                if (opcode === Const.op_connect) {
                    s.write(buildOpCondAcceptSrpEmpty(protocolVersion));
                } else if (opcode === Const.op_cont_auth) {
                    contAuthCount++;
                    if (contAuthCount === 1) {
                        // client sent its public key A – reply with EMPTY data
                        s.write(buildOpContAuthEmpty());
                    } else if (contAuthCount === 2) {
                        // client restarted the handshake – now deliver salt + B
                        s.write(buildOpContAuthSalt(SRP_TEST_SALT, serverKeys.public));
                    } else {
                        // client sent M1 – finish auth
                        s.write(Buffer.concat([buildOpContAuthEmpty(), buildOpAccept(protocolVersion)]));
                    }
                } else if (opcode === Const.op_attach) {
                    s.write(buildOpResponse(42));
                } else if (opcode === Const.op_detach) {
                    s.write(buildOpResponse(0));
                    s.end();
                }
                return buf.length;
            });
        });

        try {
            const db = await withMockSrpAttach(port);
            assert.ok(db, 'db should attach after the handshake restart');
            assert.strictEqual(contAuthCount, 3, 'client should send A, restart with A, then M1');
            await new Promise((resolve, reject) => db.detach(e => (e ? reject(e) : resolve())));
        } finally {
            await stopMockServer(server);
        }
    });

    it('should fail with an error (not an uncaughtException) when the server keeps sending empty op_cont_auth', async function () {
        const clientSockets = [];
        const { server, port } = await startMockServer(socket => {
            clientSockets.push(socket);
            makeFullDispatcher(socket, (s, opcode, buf) => {
                if (opcode === Const.op_connect) {
                    s.write(buildOpCondAcceptSrpEmpty(Const.PROTOCOL_VERSION16));
                } else if (opcode === Const.op_cont_auth) {
                    s.write(buildOpContAuthEmpty());   // misbehaving server: always empty
                }
                return buf.length;
            });
        });

        try {
            await assert.rejects(withMockSrpAttach(port), Error);
        } finally {
            clientSockets.forEach(s => s.destroy());
            await stopMockServer(server);
        }
    });

    it('should turn a synchronous decoder fault into a connection error (not an uncaughtException)', async function () {
        const clientSockets = [];
        const { server, port } = await startMockServer(socket => {
            clientSockets.push(socket);
            makeFullDispatcher(socket, (s, opcode, buf) => {
                if (opcode === Const.op_connect) {
                    s.write(buildOpCondAcceptSrpEmpty(Const.PROTOCOL_VERSION16));
                } else if (opcode === Const.op_cont_auth) {
                    // server key B that is not valid hex
                    s.write(buildOpContAuthSalt(SRP_TEST_SALT, null, 'zz'.repeat(32)));
                }
                return buf.length;
            });
        });

        try {
            await assert.rejects(withMockSrpAttach(port), Error);
        } finally {
            clientSockets.forEach(s => s.destroy());
            await stopMockServer(server);
        }
    });
});

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

// ---------------------------------------------------------------------------
// Failed connections must not leak their socket
// ---------------------------------------------------------------------------

describe('tonmat fork – failed connections release their socket', function () {

    /** Server that authenticates, then rejects op_attach with I/O error. */
    function startRejectingAttachServer(onClientSocket) {
        return startMockServer(socket => {
            onClientSocket(trackClose(socket));
            makeFullDispatcher(socket, (s, opcode, buf) => {
                if (opcode === Const.op_connect) {
                    s.write(buildOpAcceptData());
                } else if (opcode === Const.op_attach) {
                    s.write(buildOpResponseError(Const.isc_io_error || 335544344,
                        'open', '/mock/missing.fdb'));
                }
                return buf.length;
            });
        });
    }

    it('should close the socket when op_attach fails (e.g. missing database file)', async function () {
        let serverSide;
        const { server, port } = await startRejectingAttachServer(s => { serverSide = s; });

        try {
            await assert.rejects(attachAsync(Object.assign({}, MOCK_OPTIONS, { port })),
                err => err.gdscode === 335544344);
            await whenClientCloses(serverSide, 1000);
        } finally {
            if (serverSide) serverSide.destroy();
            await stopMockServer(server);
        }
    });

    it('should close the socket when op_connect is rejected', async function () {
        let serverSide;
        const { server, port } = await startMockServer(socket => {
            serverSide = trackClose(socket);
            makeFullDispatcher(socket, (s, opcode, buf) => {
                if (opcode === Const.op_connect) {
                    s.write(buildOpResponseError(335544472)); // login rejected
                }
                return buf.length;
            });
        });

        try {
            await assert.rejects(attachAsync(Object.assign({}, MOCK_OPTIONS, { port })), Error);
            await whenClientCloses(serverSide, 1000);
        } finally {
            if (serverSide) serverSide.destroy();
            await stopMockServer(server);
        }
    });

    it('should free the pool slot and close the socket when a pooled attach fails', async function () {
        const serverSides = [];
        const { server, port } = await startRejectingAttachServer(s => { serverSides.push(s); });
        const pool = Firebird.pool(1, Object.assign({}, MOCK_OPTIONS, { port }));

        try {
            for (let i = 0; i < 3; i++) {
                await assert.rejects(new Promise((resolve, reject) => {
                    pool.get((err, db) => (err ? reject(err) : resolve(db)));
                }), err => err.gdscode === 335544344);
            }
            assert.strictEqual(serverSides.length, 3, 'every get() should retry the attach');
            assert.strictEqual(pool._creating, 0, 'failed attaches must release their slot');
            assert.strictEqual(pool.totalCount, 0);
            await Promise.all(serverSides.map(s => whenClientCloses(s, 1000)));
        } finally {
            pool.destroy();
            serverSides.forEach(s => s.destroy());
            await stopMockServer(server);
        }
    });

    it('should report the outcome of an attach once, even if the socket fails afterwards', async function () {
        let serverSide;
        const { server, port } = await startMockServer(socket => {
            serverSide = socket;
            makeFullDispatcher(socket, (s, opcode, buf) => {
                if (opcode === Const.op_connect) {
                    s.write(buildOpAcceptData());
                } else if (opcode === Const.op_attach) {
                    s.write(buildOpResponse(42));
                }
                return buf.length;
            });
        });

        let calls = 0;
        try {
            const db = await new Promise((resolve, reject) => {
                Firebird.attach(Object.assign({}, MOCK_OPTIONS, { port }), (err, d) => {
                    calls++;
                    if (err) reject(err); else resolve(d);
                });
            });
            db.on('error', () => {});   // the reset below is expected
            // RST instead of FIN: the client socket emits 'error' (ECONNRESET)
            serverSide.resetAndDestroy();
            await new Promise(resolve => setTimeout(resolve, 200));
            assert.strictEqual(calls, 1, 'the attach callback must not fire again on a later socket error');
        } finally {
            await stopMockServer(server);
        }
    });
});

// ---------------------------------------------------------------------------
// Same leak against a real server: attaching a database file that does not
// exist is the production case (one attach per missing branch database).
// ---------------------------------------------------------------------------

describe('tonmat fork – failed attach against a real server', function () {

    it('should close the socket after the server reports a missing database file', async function () {
        const options = Object.assign({}, Config.default, {
            database: Config.default.database.replace(/[^/\\]+$/, 'missing-' + Date.now() + '.fdb'),
        });

        await assert.rejects(attachAsync(options), Error);
        const cnx = Firebird.connection;
        assert.ok(cnx, 'attach() exposes its connection');
        // closing is asynchronous: give the FIN/close round trip a moment
        for (let i = 0; i < 50 && !cnx._socket.destroyed; i++) {
            await new Promise(resolve => setTimeout(resolve, 20));
        }
        assert.ok(cnx._socket.destroyed, 'the failed connection must not keep its socket open');
    });
});
