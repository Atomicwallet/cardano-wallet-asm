import * as wasm from './cardano_wallet_browser.asm';

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

let cachegetUint8Memory0 = null;
function getUint8Memory0() {
    if (cachegetUint8Memory0 === null || cachegetUint8Memory0.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory0;
}

function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

const heap = new Array(32);

heap.fill(undefined);

heap.push(undefined, null, true, false);

let heap_next = heap.length;

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function getObject(idx) { return heap[idx]; }

function dropObject(idx) {
    if (idx < 36) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let WASM_VECTOR_LEN = 0;

let cachedTextEncoder = new TextEncoder('utf-8');

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length);
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len);

    const mem = getUint8Memory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3);
        const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachegetInt32Memory0 = null;
function getInt32Memory0() {
    if (cachegetInt32Memory0 === null || cachegetInt32Memory0.buffer !== wasm.memory.buffer) {
        cachegetInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachegetInt32Memory0;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
    return instance.ptr;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1);
    getUint8Memory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}
/**
* @param {Entropy} entropy
* @param {Uint8Array} iv
* @param {string} password
* @returns {any}
*/
export function paper_wallet_scramble(entropy, iv, password) {
    _assertClass(entropy, Entropy);
    var ptr0 = passArray8ToWasm0(iv, wasm.__wbindgen_malloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    var ret = wasm.paper_wallet_scramble(entropy.ptr, ptr0, len0, ptr1, len1);
    return takeObject(ret);
}

/**
* @param {Uint8Array} paper
* @param {string} password
* @returns {Entropy}
*/
export function paper_wallet_unscramble(paper, password) {
    var ptr0 = passArray8ToWasm0(paper, wasm.__wbindgen_malloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    var ret = wasm.paper_wallet_unscramble(ptr0, len0, ptr1, len1);
    return Entropy.__wrap(ret);
}

/**
* encrypt the given data with a password, a salt and a nonce
*
* Salt: must be 32 bytes long;
* Nonce: must be 12 bytes long;
* @param {string} password
* @param {Uint8Array} salt
* @param {Uint8Array} nonce
* @param {Uint8Array} data
* @returns {any}
*/
export function password_encrypt(password, salt, nonce, data) {
    var ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
    var len1 = WASM_VECTOR_LEN;
    var ptr2 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
    var len2 = WASM_VECTOR_LEN;
    var ptr3 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
    var len3 = WASM_VECTOR_LEN;
    var ret = wasm.password_encrypt(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return takeObject(ret);
}

/**
* decrypt the data with the password
* @param {string} password
* @param {Uint8Array} encrypted_data
* @returns {any}
*/
export function password_decrypt(password, encrypted_data) {
    var ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ptr1 = passArray8ToWasm0(encrypted_data, wasm.__wbindgen_malloc);
    var len1 = WASM_VECTOR_LEN;
    var ret = wasm.password_decrypt(ptr0, len0, ptr1, len1);
    return takeObject(ret);
}

/**
*/
export class AccountIndex {

    static __wrap(ptr) {
        const obj = Object.create(AccountIndex.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_accountindex_free(ptr);
    }
    /**
    * @param {number} index
    * @returns {AccountIndex}
    */
    static new(index) {
        var ret = wasm.accountindex_new(index);
        return AccountIndex.__wrap(ret);
    }
}
/**
*/
export class Address {

    static __wrap(ptr) {
        const obj = Object.create(Address.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_address_free(ptr);
    }
    /**
    * @returns {string}
    */
    to_base58() {
        try {
            wasm.address_to_base58(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @param {string} s
    * @returns {Address}
    */
    static from_base58(s) {
        var ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.address_from_base58(ptr0, len0);
        return Address.__wrap(ret);
    }
    /**
    * @param {string} s
    * @returns {boolean}
    */
    static is_valid(s) {
        var ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.address_is_valid(ptr0, len0);
        return ret !== 0;
    }
}
/**
*/
export class AddressKeyIndex {

    static __wrap(ptr) {
        const obj = Object.create(AddressKeyIndex.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_addresskeyindex_free(ptr);
    }
    /**
    * @param {number} index
    * @returns {AddressKeyIndex}
    */
    static new(index) {
        var ret = wasm.addresskeyindex_new(index);
        return AddressKeyIndex.__wrap(ret);
    }
}
/**
*/
export class Bip44AccountPrivate {

    static __wrap(ptr) {
        const obj = Object.create(Bip44AccountPrivate.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_bip44accountprivate_free(ptr);
    }
    /**
    * @param {PrivateKey} key
    * @param {DerivationScheme} derivation_scheme
    * @returns {Bip44AccountPrivate}
    */
    static new(key, derivation_scheme) {
        _assertClass(key, PrivateKey);
        var ptr0 = key.ptr;
        key.ptr = 0;
        _assertClass(derivation_scheme, DerivationScheme);
        var ptr1 = derivation_scheme.ptr;
        derivation_scheme.ptr = 0;
        var ret = wasm.bip44accountprivate_new(ptr0, ptr1);
        return Bip44AccountPrivate.__wrap(ret);
    }
    /**
    * @returns {Bip44AccountPublic}
    */
    public() {
        var ret = wasm.bip44accountprivate_public(this.ptr);
        return Bip44AccountPublic.__wrap(ret);
    }
    /**
    * @param {boolean} internal
    * @returns {Bip44ChainPrivate}
    */
    bip44_chain(internal) {
        var ret = wasm.bip44accountprivate_bip44_chain(this.ptr, internal);
        return Bip44ChainPrivate.__wrap(ret);
    }
    /**
    * @returns {PrivateKey}
    */
    key() {
        var ret = wasm.bip44accountprivate_key(this.ptr);
        return PrivateKey.__wrap(ret);
    }
}
/**
*/
export class Bip44AccountPublic {

    static __wrap(ptr) {
        const obj = Object.create(Bip44AccountPublic.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_bip44accountpublic_free(ptr);
    }
    /**
    * @param {PublicKey} key
    * @param {DerivationScheme} derivation_scheme
    * @returns {Bip44AccountPublic}
    */
    static new(key, derivation_scheme) {
        _assertClass(key, PublicKey);
        var ptr0 = key.ptr;
        key.ptr = 0;
        _assertClass(derivation_scheme, DerivationScheme);
        var ptr1 = derivation_scheme.ptr;
        derivation_scheme.ptr = 0;
        var ret = wasm.bip44accountpublic_new(ptr0, ptr1);
        return Bip44AccountPublic.__wrap(ret);
    }
    /**
    * @param {boolean} internal
    * @returns {Bip44ChainPublic}
    */
    bip44_chain(internal) {
        var ret = wasm.bip44accountpublic_bip44_chain(this.ptr, internal);
        return Bip44ChainPublic.__wrap(ret);
    }
    /**
    * @returns {PublicKey}
    */
    key() {
        var ret = wasm.bip44accountpublic_key(this.ptr);
        return PublicKey.__wrap(ret);
    }
}
/**
*/
export class Bip44ChainPrivate {

    static __wrap(ptr) {
        const obj = Object.create(Bip44ChainPrivate.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_bip44chainprivate_free(ptr);
    }
    /**
    * @param {PrivateKey} key
    * @param {DerivationScheme} derivation_scheme
    * @returns {Bip44ChainPrivate}
    */
    static new(key, derivation_scheme) {
        _assertClass(key, PrivateKey);
        var ptr0 = key.ptr;
        key.ptr = 0;
        _assertClass(derivation_scheme, DerivationScheme);
        var ptr1 = derivation_scheme.ptr;
        derivation_scheme.ptr = 0;
        var ret = wasm.bip44chainprivate_new(ptr0, ptr1);
        return Bip44ChainPrivate.__wrap(ret);
    }
    /**
    * @returns {Bip44ChainPublic}
    */
    public() {
        var ret = wasm.bip44chainprivate_public(this.ptr);
        return Bip44ChainPublic.__wrap(ret);
    }
    /**
    * @param {AddressKeyIndex} index
    * @returns {PrivateKey}
    */
    address_key(index) {
        _assertClass(index, AddressKeyIndex);
        var ptr0 = index.ptr;
        index.ptr = 0;
        var ret = wasm.bip44chainprivate_address_key(this.ptr, ptr0);
        return PrivateKey.__wrap(ret);
    }
    /**
    * @returns {PrivateKey}
    */
    key() {
        var ret = wasm.bip44chainprivate_key(this.ptr);
        return PrivateKey.__wrap(ret);
    }
}
/**
*/
export class Bip44ChainPublic {

    static __wrap(ptr) {
        const obj = Object.create(Bip44ChainPublic.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_bip44chainpublic_free(ptr);
    }
    /**
    * @param {PublicKey} key
    * @param {DerivationScheme} derivation_scheme
    * @returns {Bip44ChainPublic}
    */
    static new(key, derivation_scheme) {
        _assertClass(key, PublicKey);
        var ptr0 = key.ptr;
        key.ptr = 0;
        _assertClass(derivation_scheme, DerivationScheme);
        var ptr1 = derivation_scheme.ptr;
        derivation_scheme.ptr = 0;
        var ret = wasm.bip44chainpublic_new(ptr0, ptr1);
        return Bip44ChainPublic.__wrap(ret);
    }
    /**
    * @param {AddressKeyIndex} index
    * @returns {PublicKey}
    */
    address_key(index) {
        _assertClass(index, AddressKeyIndex);
        var ptr0 = index.ptr;
        index.ptr = 0;
        var ret = wasm.bip44chainpublic_address_key(this.ptr, ptr0);
        return PublicKey.__wrap(ret);
    }
    /**
    * @returns {PublicKey}
    */
    key() {
        var ret = wasm.bip44chainpublic_key(this.ptr);
        return PublicKey.__wrap(ret);
    }
}
/**
* Root Private Key of a BIP44 HD Wallet
*/
export class Bip44RootPrivateKey {

    static __wrap(ptr) {
        const obj = Object.create(Bip44RootPrivateKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_bip44rootprivatekey_free(ptr);
    }
    /**
    * @param {PrivateKey} key
    * @param {DerivationScheme} derivation_scheme
    * @returns {Bip44RootPrivateKey}
    */
    static new(key, derivation_scheme) {
        _assertClass(key, PrivateKey);
        var ptr0 = key.ptr;
        key.ptr = 0;
        _assertClass(derivation_scheme, DerivationScheme);
        var ptr1 = derivation_scheme.ptr;
        derivation_scheme.ptr = 0;
        var ret = wasm.bip44rootprivatekey_new(ptr0, ptr1);
        return Bip44RootPrivateKey.__wrap(ret);
    }
    /**
    * recover a wallet from the given mnemonic words and the given password
    *
    * To recover an icarus wallet:
    * * 15 mnemonic words;
    * * empty password;
    * @param {Entropy} entropy
    * @param {string} password
    * @returns {Bip44RootPrivateKey}
    */
    static recover(entropy, password) {
        _assertClass(entropy, Entropy);
        var ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.bip44rootprivatekey_recover(entropy.ptr, ptr0, len0);
        return Bip44RootPrivateKey.__wrap(ret);
    }
    /**
    * @param {AccountIndex} index
    * @returns {Bip44AccountPrivate}
    */
    bip44_account(index) {
        _assertClass(index, AccountIndex);
        var ptr0 = index.ptr;
        index.ptr = 0;
        var ret = wasm.bip44rootprivatekey_bip44_account(this.ptr, ptr0);
        return Bip44AccountPrivate.__wrap(ret);
    }
    /**
    * @returns {PrivateKey}
    */
    key() {
        var ret = wasm.bip44rootprivatekey_key(this.ptr);
        return PrivateKey.__wrap(ret);
    }
}
/**
* setting of the blockchain
*
* This includes the `ProtocolMagic` a discriminant value to differentiate
* different instances of the cardano blockchain (Mainnet, Testnet... ).
*/
export class BlockchainSettings {

    static __wrap(ptr) {
        const obj = Object.create(BlockchainSettings.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_blockchainsettings_free(ptr);
    }
    /**
    * serialize into a JsValue object. Allowing the client to store the settings
    * or see changes in the settings or change the settings.
    *
    * Note that this is not recommended to change the settings on the fly. Doing
    * so you might not be able to recover your funds anymore or to send new
    * transactions.
    * @returns {any}
    */
    to_json() {
        var ret = wasm.blockchainsettings_to_json(this.ptr);
        return takeObject(ret);
    }
    /**
    * retrieve the object from a JsValue.
    * @param {any} value
    * @returns {BlockchainSettings}
    */
    static from_json(value) {
        var ret = wasm.blockchainsettings_from_json(addHeapObject(value));
        return BlockchainSettings.__wrap(ret);
    }
    /**
    * default settings to work with Cardano Mainnet
    * @returns {BlockchainSettings}
    */
    static mainnet() {
        var ret = wasm.blockchainsettings_mainnet();
        return BlockchainSettings.__wrap(ret);
    }
}
/**
*/
export class Coin {

    static __wrap(ptr) {
        const obj = Object.create(Coin.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_coin_free(ptr);
    }
    /**
    */
    constructor() {
        var ret = wasm.coin_new();
        return Coin.__wrap(ret);
    }
    /**
    * @param {string} s
    * @returns {Coin}
    */
    static from_str(s) {
        var ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.coin_from_str(ptr0, len0);
        return Coin.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_str() {
        try {
            wasm.coin_to_str(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @param {number} ada
    * @param {number} lovelace
    * @returns {Coin}
    */
    static from(ada, lovelace) {
        var ret = wasm.coin_from(ada, lovelace);
        return Coin.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    ada() {
        var ret = wasm.coin_ada(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {number}
    */
    lovelace() {
        var ret = wasm.coin_lovelace(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {Coin} other
    * @returns {Coin}
    */
    add(other) {
        _assertClass(other, Coin);
        var ret = wasm.coin_add(this.ptr, other.ptr);
        return Coin.__wrap(ret);
    }
}
/**
*/
export class CoinDiff {

    static __wrap(ptr) {
        const obj = Object.create(CoinDiff.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_coindiff_free(ptr);
    }
    /**
    * @returns {boolean}
    */
    is_zero() {
        var ret = wasm.coindiff_is_zero(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_negative() {
        var ret = wasm.coindiff_is_negative(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_positive() {
        var ret = wasm.coindiff_is_positive(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {Coin}
    */
    value() {
        var ret = wasm.coindiff_value(this.ptr);
        return Coin.__wrap(ret);
    }
}
/**
*/
export class DaedalusAddressChecker {

    static __wrap(ptr) {
        const obj = Object.create(DaedalusAddressChecker.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_daedalusaddresschecker_free(ptr);
    }
    /**
    * create a new address checker for the given daedalus address
    * @param {DaedalusWallet} wallet
    * @returns {DaedalusAddressChecker}
    */
    static new(wallet) {
        _assertClass(wallet, DaedalusWallet);
        var ret = wasm.daedalusaddresschecker_new(wallet.ptr);
        return DaedalusAddressChecker.__wrap(ret);
    }
    /**
    * check that we own the given address.
    *
    * This is only possible like this because some payload is embedded in the
    * address that only our wallet can decode. Once decoded we can retrieve
    * the associated private key.
    *
    * The return private key is the key needed to sign the transaction to unlock
    * UTxO associated to the address.
    * @param {Address} address
    * @returns {DaedalusCheckedAddress}
    */
    check_address(address) {
        _assertClass(address, Address);
        var ret = wasm.daedalusaddresschecker_check_address(this.ptr, address.ptr);
        return DaedalusCheckedAddress.__wrap(ret);
    }
}
/**
* result value of the check_address function of the DaedalusAddressChecker.
*
* If the address passed to check_address was recognised by the daedalus wallet
* then this object will contain the private key associated to this wallet
* private key necessary to sign transactions
*/
export class DaedalusCheckedAddress {

    static __wrap(ptr) {
        const obj = Object.create(DaedalusCheckedAddress.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_daedaluscheckedaddress_free(ptr);
    }
    /**
    * return if the value contains the private key (i.e. the check_address
    * recognised an address).
    * @returns {boolean}
    */
    is_checked() {
        var ret = wasm.daedaluscheckedaddress_is_checked(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {PrivateKey}
    */
    private_key() {
        var ret = wasm.daedaluscheckedaddress_private_key(this.ptr);
        return PrivateKey.__wrap(ret);
    }
}
/**
*/
export class DaedalusWallet {

    static __wrap(ptr) {
        const obj = Object.create(DaedalusWallet.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_daedaluswallet_free(ptr);
    }
    /**
    * @param {PrivateKey} key
    * @returns {DaedalusWallet}
    */
    static new(key) {
        _assertClass(key, PrivateKey);
        var ptr0 = key.ptr;
        key.ptr = 0;
        var ret = wasm.daedaluswallet_new(ptr0);
        return DaedalusWallet.__wrap(ret);
    }
    /**
    * @returns {PrivateKey}
    */
    master_key() {
        var ret = wasm.daedaluswallet_master_key(this.ptr);
        return PrivateKey.__wrap(ret);
    }
    /**
    * @param {Entropy} entropy
    * @returns {DaedalusWallet}
    */
    static recover(entropy) {
        _assertClass(entropy, Entropy);
        var ret = wasm.daedaluswallet_recover(entropy.ptr);
        return DaedalusWallet.__wrap(ret);
    }
}
/**
* There is a special function to use when deriving Addresses. This function
* has been revised to offer stronger properties. This is why there is a
* V2 derivation scheme. The V1 being the legacy one still used in daedalus
* now a days.
*
* It is strongly advised to use V2 as the V1 is deprecated since April 2018.
* Its support is already provided for backward compatibility with old
* addresses.
*/
export class DerivationScheme {

    static __wrap(ptr) {
        const obj = Object.create(DerivationScheme.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_derivationscheme_free(ptr);
    }
    /**
    * deprecated, provided here only for backward compatibility with
    * Daedalus\' addresses
    * @returns {DerivationScheme}
    */
    static v1() {
        var ret = wasm.derivationscheme_v1();
        return DerivationScheme.__wrap(ret);
    }
    /**
    * the recommended settings
    * @returns {DerivationScheme}
    */
    static v2() {
        var ret = wasm.derivationscheme_v2();
        return DerivationScheme.__wrap(ret);
    }
}
/**
* the entropy associated to mnemonics. This is a bytes representation of the
* mnemonics the user has to remember how to generate the root key of an
* HD Wallet.
*
* TODO: interface to generate a new entropy
*
* # Security considerations
*
* * do not store this value without encrypting it;
* * do not leak the mnemonics;
* * make sure the user remembers the mnemonics string;
*/
export class Entropy {

    static __wrap(ptr) {
        const obj = Object.create(Entropy.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_entropy_free(ptr);
    }
    /**
    * retrieve the initial entropy of a wallet from the given
    * english mnemonics.
    * @param {string} mnemonics
    * @returns {Entropy}
    */
    static from_english_mnemonics(mnemonics) {
        var ptr0 = passStringToWasm0(mnemonics, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.entropy_from_english_mnemonics(ptr0, len0);
        return Entropy.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_english_mnemonics() {
        try {
            wasm.entropy_to_english_mnemonics(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @returns {any}
    */
    to_array() {
        var ret = wasm.entropy_to_array(this.ptr);
        return takeObject(ret);
    }
}
/**
*/
export class InputSelectionBuilder {

    static __wrap(ptr) {
        const obj = Object.create(InputSelectionBuilder.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_inputselectionbuilder_free(ptr);
    }
    /**
    * @returns {InputSelectionBuilder}
    */
    static first_match_first() {
        var ret = wasm.inputselectionbuilder_first_match_first();
        return InputSelectionBuilder.__wrap(ret);
    }
    /**
    * @returns {InputSelectionBuilder}
    */
    static largest_first() {
        var ret = wasm.inputselectionbuilder_largest_first();
        return InputSelectionBuilder.__wrap(ret);
    }
    /**
    * @param {Coin} dust_threshold
    * @returns {InputSelectionBuilder}
    */
    static blackjack(dust_threshold) {
        _assertClass(dust_threshold, Coin);
        var ptr0 = dust_threshold.ptr;
        dust_threshold.ptr = 0;
        var ret = wasm.inputselectionbuilder_blackjack(ptr0);
        return InputSelectionBuilder.__wrap(ret);
    }
    /**
    * @param {TxInput} tx_input
    */
    add_input(tx_input) {
        _assertClass(tx_input, TxInput);
        wasm.inputselectionbuilder_add_input(this.ptr, tx_input.ptr);
    }
    /**
    * @param {TxOut} output
    */
    add_output(output) {
        _assertClass(output, TxOut);
        wasm.inputselectionbuilder_add_output(this.ptr, output.ptr);
    }
    /**
    * @param {LinearFeeAlgorithm} fee_algorithm
    * @param {OutputPolicy} output_policy
    * @returns {InputSelectionResult}
    */
    select_inputs(fee_algorithm, output_policy) {
        _assertClass(fee_algorithm, LinearFeeAlgorithm);
        _assertClass(output_policy, OutputPolicy);
        var ret = wasm.inputselectionbuilder_select_inputs(this.ptr, fee_algorithm.ptr, output_policy.ptr);
        return InputSelectionResult.__wrap(ret);
    }
}
/**
*/
export class InputSelectionResult {

    static __wrap(ptr) {
        const obj = Object.create(InputSelectionResult.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_inputselectionresult_free(ptr);
    }
    /**
    * @param {TxoPointer} txo_pointer
    * @returns {boolean}
    */
    is_input(txo_pointer) {
        _assertClass(txo_pointer, TxoPointer);
        var ret = wasm.inputselectionresult_is_input(this.ptr, txo_pointer.ptr);
        return ret !== 0;
    }
    /**
    * @returns {Coin}
    */
    estimated_fees() {
        var ret = wasm.inputselectionresult_estimated_fees(this.ptr);
        return Coin.__wrap(ret);
    }
    /**
    * @returns {Coin}
    */
    estimated_change() {
        var ret = wasm.inputselectionresult_estimated_change(this.ptr);
        return Coin.__wrap(ret);
    }
}
/**
* This is the linear fee algorithm used buy the current cardano blockchain.
*
* However it is possible the linear fee algorithm may change its settings:
*
* It is currently a function `fee(n) = a * x + b`. `a` and `b` can be
* re-configured by a protocol update. Users of this object need to be aware
* that it may change and that they might need to update its settings.
*/
export class LinearFeeAlgorithm {

    static __wrap(ptr) {
        const obj = Object.create(LinearFeeAlgorithm.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_linearfeealgorithm_free(ptr);
    }
    /**
    * this is the default mainnet linear fee algorithm. It is also known to work
    * with the staging network and the current testnet.
    * @returns {LinearFeeAlgorithm}
    */
    static default() {
        var ret = wasm.linearfeealgorithm_default();
        return LinearFeeAlgorithm.__wrap(ret);
    }
}
/**
* This is the Output policy for automatic Input selection.
*/
export class OutputPolicy {

    static __wrap(ptr) {
        const obj = Object.create(OutputPolicy.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_outputpolicy_free(ptr);
    }
    /**
    * requires to send back all the spare changes to only one given address
    * @param {Address} address
    * @returns {OutputPolicy}
    */
    static change_to_one_address(address) {
        _assertClass(address, Address);
        var ptr0 = address.ptr;
        address.ptr = 0;
        var ret = wasm.outputpolicy_change_to_one_address(ptr0);
        return OutputPolicy.__wrap(ret);
    }
}
/**
* A given private key. You can use this key to sign transactions.
*
* # security considerations
*
* * do not store this key without encrypting it;
* * if leaked anyone can _spend_ a UTxO (Unspent Transaction Output)
*   with it;
*/
export class PrivateKey {

    static __wrap(ptr) {
        const obj = Object.create(PrivateKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_privatekey_free(ptr);
    }
    /**
    * create a new private key from a given Entropy
    * @param {Entropy} entropy
    * @param {string} password
    * @returns {PrivateKey}
    */
    static new(entropy, password) {
        _assertClass(entropy, Entropy);
        var ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.privatekey_new(entropy.ptr, ptr0, len0);
        return PrivateKey.__wrap(ret);
    }
    /**
    * retrieve a private key from the given hexadecimal string
    * @param {string} hex
    * @returns {PrivateKey}
    */
    static from_hex(hex) {
        var ptr0 = passStringToWasm0(hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.privatekey_from_hex(ptr0, len0);
        return PrivateKey.__wrap(ret);
    }
    /**
    * convert the private key to an hexadecimal string
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.privatekey_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * get the public key associated to this private key
    * @returns {PublicKey}
    */
    public() {
        var ret = wasm.privatekey_public(this.ptr);
        return PublicKey.__wrap(ret);
    }
    /**
    * sign some bytes with this private key
    * @param {Uint8Array} data
    * @returns {Signature}
    */
    sign(data) {
        var ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.privatekey_sign(this.ptr, ptr0, len0);
        return Signature.__wrap(ret);
    }
    /**
    * derive this private key with the given index.
    *
    * # Security considerations
    *
    * * prefer the use of DerivationScheme::v2 when possible;
    * * hard derivation index cannot be soft derived with the public key
    *
    * # Hard derivation vs Soft derivation
    *
    * If you pass an index below 0x80000000 then it is a soft derivation.
    * The advantage of soft derivation is that it is possible to derive the
    * public key too. I.e. derivation the private key with a soft derivation
    * index and then retrieving the associated public key is equivalent to
    * deriving the public key associated to the parent private key.
    *
    * Hard derivation index does not allow public key derivation.
    *
    * This is why deriving the private key should not fail while deriving
    * the public key may fail (if the derivation index is invalid).
    * @param {DerivationScheme} derivation_scheme
    * @param {number} index
    * @returns {PrivateKey}
    */
    derive(derivation_scheme, index) {
        _assertClass(derivation_scheme, DerivationScheme);
        var ptr0 = derivation_scheme.ptr;
        derivation_scheme.ptr = 0;
        var ret = wasm.privatekey_derive(this.ptr, ptr0, index);
        return PrivateKey.__wrap(ret);
    }
}
/**
*/
export class PrivateRedeemKey {

    static __wrap(ptr) {
        const obj = Object.create(PrivateRedeemKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_privateredeemkey_free(ptr);
    }
    /**
    * retrieve the private redeeming key from the given bytes (expect 64 bytes)
    * @param {Uint8Array} bytes
    * @returns {PrivateRedeemKey}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.privateredeemkey_from_bytes(ptr0, len0);
        return PrivateRedeemKey.__wrap(ret);
    }
    /**
    * retrieve a private key from the given hexadecimal string
    * @param {string} hex
    * @returns {PrivateRedeemKey}
    */
    static from_hex(hex) {
        var ptr0 = passStringToWasm0(hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.privateredeemkey_from_hex(ptr0, len0);
        return PrivateRedeemKey.__wrap(ret);
    }
    /**
    * convert the private key to an hexadecimal string
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.privateredeemkey_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * get the public key associated to this private key
    * @returns {PublicRedeemKey}
    */
    public() {
        var ret = wasm.privateredeemkey_public(this.ptr);
        return PublicRedeemKey.__wrap(ret);
    }
    /**
    * sign some bytes with this private key
    * @param {Uint8Array} data
    * @returns {RedeemSignature}
    */
    sign(data) {
        var ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.privateredeemkey_sign(this.ptr, ptr0, len0);
        return RedeemSignature.__wrap(ret);
    }
}
/**
* The public key associated to a given private key.
*
* It is not possible to sign (and then spend) with a public key.
* However it is possible to verify a Signature.
*
* # Security Consideration
*
* * Leaking a public key leads to privacy loss and in case of bip44 may compromise your wallet
*  (see hardened indices for more details)
*/
export class PublicKey {

    static __wrap(ptr) {
        const obj = Object.create(PublicKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_publickey_free(ptr);
    }
    /**
    * @param {string} hex
    * @returns {PublicKey}
    */
    static from_hex(hex) {
        var ptr0 = passStringToWasm0(hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.publickey_from_hex(ptr0, len0);
        return PublicKey.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.publickey_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @param {Uint8Array} data
    * @param {Signature} signature
    * @returns {boolean}
    */
    verify(data, signature) {
        var ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        _assertClass(signature, Signature);
        var ret = wasm.publickey_verify(this.ptr, ptr0, len0, signature.ptr);
        return ret !== 0;
    }
    /**
    * derive this public key with the given index.
    *
    * # Errors
    *
    * If the index is not a soft derivation index (< 0x80000000) then
    * calling this method will fail.
    *
    * # Security considerations
    *
    * * prefer the use of DerivationScheme::v2 when possible;
    * * hard derivation index cannot be soft derived with the public key
    *
    * # Hard derivation vs Soft derivation
    *
    * If you pass an index below 0x80000000 then it is a soft derivation.
    * The advantage of soft derivation is that it is possible to derive the
    * public key too. I.e. derivation the private key with a soft derivation
    * index and then retrieving the associated public key is equivalent to
    * deriving the public key associated to the parent private key.
    *
    * Hard derivation index does not allow public key derivation.
    *
    * This is why deriving the private key should not fail while deriving
    * the public key may fail (if the derivation index is invalid).
    * @param {DerivationScheme} derivation_scheme
    * @param {number} index
    * @returns {PublicKey}
    */
    derive(derivation_scheme, index) {
        _assertClass(derivation_scheme, DerivationScheme);
        var ptr0 = derivation_scheme.ptr;
        derivation_scheme.ptr = 0;
        var ret = wasm.publickey_derive(this.ptr, ptr0, index);
        return PublicKey.__wrap(ret);
    }
    /**
    * get the bootstrap era address. I.E. this is an address without
    * stake delegation.
    * @param {BlockchainSettings} blockchain_settings
    * @returns {Address}
    */
    bootstrap_era_address(blockchain_settings) {
        _assertClass(blockchain_settings, BlockchainSettings);
        var ret = wasm.publickey_bootstrap_era_address(this.ptr, blockchain_settings.ptr);
        return Address.__wrap(ret);
    }
}
/**
*/
export class PublicRedeemKey {

    static __wrap(ptr) {
        const obj = Object.create(PublicRedeemKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_publicredeemkey_free(ptr);
    }
    /**
    * retrieve a public key from the given hexadecimal string
    * @param {string} hex
    * @returns {PublicRedeemKey}
    */
    static from_hex(hex) {
        var ptr0 = passStringToWasm0(hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.publicredeemkey_from_hex(ptr0, len0);
        return PublicRedeemKey.__wrap(ret);
    }
    /**
    * convert the public key to an hexadecimal string
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.publicredeemkey_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * verify the signature with the given public key
    * @param {Uint8Array} data
    * @param {RedeemSignature} signature
    * @returns {boolean}
    */
    verify(data, signature) {
        var ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        _assertClass(signature, RedeemSignature);
        var ret = wasm.publicredeemkey_verify(this.ptr, ptr0, len0, signature.ptr);
        return ret !== 0;
    }
    /**
    * generate the address for this redeeming key
    * @param {BlockchainSettings} settings
    * @returns {Address}
    */
    address(settings) {
        _assertClass(settings, BlockchainSettings);
        var ret = wasm.publicredeemkey_address(this.ptr, settings.ptr);
        return Address.__wrap(ret);
    }
}
/**
*/
export class RedeemSignature {

    static __wrap(ptr) {
        const obj = Object.create(RedeemSignature.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_redeemsignature_free(ptr);
    }
    /**
    * @param {string} hex
    * @returns {RedeemSignature}
    */
    static from_hex(hex) {
        var ptr0 = passStringToWasm0(hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.redeemsignature_from_hex(ptr0, len0);
        return RedeemSignature.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.redeemsignature_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
*/
export class Signature {

    static __wrap(ptr) {
        const obj = Object.create(Signature.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_signature_free(ptr);
    }
    /**
    * @param {string} hex
    * @returns {Signature}
    */
    static from_hex(hex) {
        var ptr0 = passStringToWasm0(hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.signature_from_hex(ptr0, len0);
        return Signature.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.signature_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
* a signed transaction, ready to be sent to the network.
*/
export class SignedTransaction {

    static __wrap(ptr) {
        const obj = Object.create(SignedTransaction.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_signedtransaction_free(ptr);
    }
    /**
    * @returns {string}
    */
    id() {
        try {
            wasm.signedtransaction_id(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @returns {any}
    */
    to_json() {
        var ret = wasm.signedtransaction_to_json(this.ptr);
        return takeObject(ret);
    }
    /**
    * @param {any} value
    * @returns {SignedTransaction}
    */
    static from_json(value) {
        var ret = wasm.signedtransaction_from_json(addHeapObject(value));
        return SignedTransaction.__wrap(ret);
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {SignedTransaction}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.signedtransaction_from_bytes(ptr0, len0);
        return SignedTransaction.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.signedtransaction_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
* a transaction type, this is not ready for sending to the network. It is only an
* intermediate type to use between the transaction builder and the transaction
* finalizer. It allows separation of concerns:
*
* 1. build the transaction on one side/thread/machine/...;
* 2. sign the transaction on the other/thread/machines/cold-wallet...;
*/
export class Transaction {

    static __wrap(ptr) {
        const obj = Object.create(Transaction.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_transaction_free(ptr);
    }
    /**
    * @returns {TransactionId}
    */
    id() {
        var ret = wasm.transaction_id(this.ptr);
        return TransactionId.__wrap(ret);
    }
    /**
    * @returns {any}
    */
    to_json() {
        var ret = wasm.transaction_to_json(this.ptr);
        return takeObject(ret);
    }
    /**
    * @param {any} value
    * @returns {Transaction}
    */
    static from_json(value) {
        var ret = wasm.transaction_from_json(addHeapObject(value));
        return Transaction.__wrap(ret);
    }
    /**
    * @returns {Transaction}
    */
    clone() {
        var ret = wasm.transaction_clone(this.ptr);
        return Transaction.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.transaction_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
* The transaction builder provides a set of tools to help build
* a valid Transaction.
*/
export class TransactionBuilder {

    static __wrap(ptr) {
        const obj = Object.create(TransactionBuilder.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_transactionbuilder_free(ptr);
    }
    /**
    * create a new transaction builder
    */
    constructor() {
        var ret = wasm.transactionbuilder_new();
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * @param {TxoPointer} txo_pointer
    * @param {Coin} value
    */
    add_input(txo_pointer, value) {
        _assertClass(txo_pointer, TxoPointer);
        _assertClass(value, Coin);
        var ptr0 = value.ptr;
        value.ptr = 0;
        wasm.transactionbuilder_add_input(this.ptr, txo_pointer.ptr, ptr0);
    }
    /**
    * @returns {Coin}
    */
    get_input_total() {
        var ret = wasm.transactionbuilder_get_input_total(this.ptr);
        return Coin.__wrap(ret);
    }
    /**
    * @param {TxOut} output
    */
    add_output(output) {
        _assertClass(output, TxOut);
        wasm.transactionbuilder_add_output(this.ptr, output.ptr);
    }
    /**
    * @param {LinearFeeAlgorithm} fee_algorithm
    * @param {OutputPolicy} policy
    * @returns {any}
    */
    apply_output_policy(fee_algorithm, policy) {
        _assertClass(fee_algorithm, LinearFeeAlgorithm);
        _assertClass(policy, OutputPolicy);
        var ret = wasm.transactionbuilder_apply_output_policy(this.ptr, fee_algorithm.ptr, policy.ptr);
        return takeObject(ret);
    }
    /**
    * @returns {Coin}
    */
    get_output_total() {
        var ret = wasm.transactionbuilder_get_output_total(this.ptr);
        return Coin.__wrap(ret);
    }
    /**
    * @param {LinearFeeAlgorithm} fee_algorithm
    * @returns {Coin}
    */
    estimate_fee(fee_algorithm) {
        _assertClass(fee_algorithm, LinearFeeAlgorithm);
        var ret = wasm.transactionbuilder_estimate_fee(this.ptr, fee_algorithm.ptr);
        return Coin.__wrap(ret);
    }
    /**
    * @param {LinearFeeAlgorithm} fee_algorithm
    * @returns {CoinDiff}
    */
    get_balance(fee_algorithm) {
        _assertClass(fee_algorithm, LinearFeeAlgorithm);
        var ret = wasm.transactionbuilder_get_balance(this.ptr, fee_algorithm.ptr);
        return CoinDiff.__wrap(ret);
    }
    /**
    * @returns {CoinDiff}
    */
    get_balance_without_fees() {
        var ret = wasm.transactionbuilder_get_balance_without_fees(this.ptr);
        return CoinDiff.__wrap(ret);
    }
    /**
    * @returns {Transaction}
    */
    make_transaction() {
        var ptr = this.ptr;
        this.ptr = 0;
        var ret = wasm.transactionbuilder_make_transaction(ptr);
        return Transaction.__wrap(ret);
    }
}
/**
*/
export class TransactionFinalized {

    static __wrap(ptr) {
        const obj = Object.create(TransactionFinalized.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_transactionfinalized_free(ptr);
    }
    /**
    * @param {Transaction} transaction
    */
    constructor(transaction) {
        _assertClass(transaction, Transaction);
        var ptr0 = transaction.ptr;
        transaction.ptr = 0;
        var ret = wasm.transactionfinalized_new(ptr0);
        return TransactionFinalized.__wrap(ret);
    }
    /**
    * @returns {TransactionId}
    */
    id() {
        var ret = wasm.transactionfinalized_id(this.ptr);
        return TransactionId.__wrap(ret);
    }
    /**
    * @param {Witness} witness
    */
    add_witness(witness) {
        _assertClass(witness, Witness);
        var ptr0 = witness.ptr;
        witness.ptr = 0;
        wasm.transactionfinalized_add_witness(this.ptr, ptr0);
    }
    /**
    * @returns {SignedTransaction}
    */
    finalize() {
        var ptr = this.ptr;
        this.ptr = 0;
        var ret = wasm.transactionfinalized_finalize(ptr);
        return SignedTransaction.__wrap(ret);
    }
}
/**
*/
export class TransactionId {

    static __wrap(ptr) {
        const obj = Object.create(TransactionId.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_transactionid_free(ptr);
    }
    /**
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.transactionid_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @param {string} s
    * @returns {TransactionId}
    */
    static from_hex(s) {
        var ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.transactionid_from_hex(ptr0, len0);
        return TransactionId.__wrap(ret);
    }
}
/**
*/
export class TransactionSignature {

    static __wrap(ptr) {
        const obj = Object.create(TransactionSignature.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_transactionsignature_free(ptr);
    }
    /**
    * @param {string} hex
    * @returns {TransactionSignature}
    */
    static from_hex(hex) {
        var ptr0 = passStringToWasm0(hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.transactionsignature_from_hex(ptr0, len0);
        return TransactionSignature.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.transactionsignature_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
*/
export class TxInput {

    static __wrap(ptr) {
        const obj = Object.create(TxInput.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_txinput_free(ptr);
    }
    /**
    * @param {TxoPointer} ptr
    * @param {TxOut} value
    * @returns {TxInput}
    */
    static new(ptr, value) {
        _assertClass(ptr, TxoPointer);
        _assertClass(value, TxOut);
        var ret = wasm.txinput_new(ptr.ptr, value.ptr);
        return TxInput.__wrap(ret);
    }
    /**
    * @returns {any}
    */
    to_json() {
        var ret = wasm.txinput_to_json(this.ptr);
        return takeObject(ret);
    }
    /**
    * @param {any} value
    * @returns {TxInput}
    */
    static from_json(value) {
        var ret = wasm.txinput_from_json(addHeapObject(value));
        return TxInput.__wrap(ret);
    }
}
/**
*/
export class TxOut {

    static __wrap(ptr) {
        const obj = Object.create(TxOut.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_txout_free(ptr);
    }
    /**
    * @param {Address} address
    * @param {Coin} value
    * @returns {TxOut}
    */
    static new(address, value) {
        _assertClass(address, Address);
        _assertClass(value, Coin);
        var ret = wasm.txout_new(address.ptr, value.ptr);
        return TxOut.__wrap(ret);
    }
    /**
    * serialize into a JsValue object
    * @returns {any}
    */
    to_json() {
        var ret = wasm.txout_to_json(this.ptr);
        return takeObject(ret);
    }
    /**
    * retrieve the object from a JsValue.
    * @param {any} value
    * @returns {TxOut}
    */
    static from_json(value) {
        var ret = wasm.txout_from_json(addHeapObject(value));
        return TxOut.__wrap(ret);
    }
}
/**
*/
export class TxoPointer {

    static __wrap(ptr) {
        const obj = Object.create(TxoPointer.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_txopointer_free(ptr);
    }
    /**
    * @param {TransactionId} id
    * @param {number} index
    * @returns {TxoPointer}
    */
    static new(id, index) {
        _assertClass(id, TransactionId);
        var ret = wasm.txopointer_new(id.ptr, index);
        return TxoPointer.__wrap(ret);
    }
    /**
    * serialize into a JsValue object
    * @returns {any}
    */
    to_json() {
        var ret = wasm.txopointer_to_json(this.ptr);
        return takeObject(ret);
    }
    /**
    * retrieve the object from a JsValue.
    * @param {any} value
    * @returns {TxoPointer}
    */
    static from_json(value) {
        var ret = wasm.txopointer_from_json(addHeapObject(value));
        return TxoPointer.__wrap(ret);
    }
}
/**
* sign the inputs of the transaction (i.e. unlock the funds the input are
* referring to).
*
* The signature must be added one by one in the same order the inputs have
* been added.
*/
export class Witness {

    static __wrap(ptr) {
        const obj = Object.create(Witness.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_witness_free(ptr);
    }
    /**
    * @param {BlockchainSettings} blockchain_settings
    * @param {PrivateKey} signing_key
    * @param {TransactionId} transaction_id
    * @returns {Witness}
    */
    static new_extended_key(blockchain_settings, signing_key, transaction_id) {
        _assertClass(blockchain_settings, BlockchainSettings);
        _assertClass(signing_key, PrivateKey);
        _assertClass(transaction_id, TransactionId);
        var ret = wasm.witness_new_extended_key(blockchain_settings.ptr, signing_key.ptr, transaction_id.ptr);
        return Witness.__wrap(ret);
    }
    /**
    * @param {BlockchainSettings} blockchain_settings
    * @param {PrivateRedeemKey} signing_key
    * @param {TransactionId} transaction_id
    * @returns {Witness}
    */
    static new_redeem_key(blockchain_settings, signing_key, transaction_id) {
        _assertClass(blockchain_settings, BlockchainSettings);
        _assertClass(signing_key, PrivateRedeemKey);
        _assertClass(transaction_id, TransactionId);
        var ret = wasm.witness_new_redeem_key(blockchain_settings.ptr, signing_key.ptr, transaction_id.ptr);
        return Witness.__wrap(ret);
    }
    /**
    * used to add signatures created by hardware wallets where we don\'t have access
    * to the private key
    * @param {PublicKey} key
    * @param {TransactionSignature} signature
    * @returns {Witness}
    */
    static from_external(key, signature) {
        _assertClass(key, PublicKey);
        _assertClass(signature, TransactionSignature);
        var ret = wasm.witness_from_external(key.ptr, signature.ptr);
        return Witness.__wrap(ret);
    }
}

export const __wbindgen_string_new = function(arg0, arg1) {
    var ret = getStringFromWasm0(arg0, arg1);
    return addHeapObject(ret);
};

export const __wbindgen_object_drop_ref = function(arg0) {
    takeObject(arg0);
};

export const __wbindgen_json_parse = function(arg0, arg1) {
    var ret = JSON.parse(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
};

export const __wbindgen_json_serialize = function(arg0, arg1) {
    const obj = getObject(arg1);
    var ret = JSON.stringify(obj === undefined ? null : obj);
    var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

export const __wbindgen_throw = function(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
};

export const __wbindgen_rethrow = function(arg0) {
    throw takeObject(arg0);
};

