import { j as building, b as base, k as private_env } from "./environment.js";
import { D as DEV, p as parse_1, s as serialize_1, c as parse_1$1 } from "./set-cookie.js";
import { r as redirect } from "./index.js";
import * as crypto$1 from "crypto";
import { createHmac } from "crypto";
import * as crypto$2 from "node:crypto";
import { createHash as createHash$1, randomFillSync, timingSafeEqual as timingSafeEqual$1, createHmac as createHmac$1, getCiphers, KeyObject, createDecipheriv, createCipheriv, createSecretKey, generateKeyPair as generateKeyPair$1, diffieHellman, pbkdf2 as pbkdf2$1, constants, publicEncrypt, privateDecrypt, createPrivateKey, createPublicKey } from "node:crypto";
import { Buffer as Buffer$1 } from "node:buffer";
import * as util from "node:util";
import { promisify, deprecate } from "node:util";
import { DrizzleAdapter } from "@auth/drizzle-adapter";
import { drizzle } from "drizzle-orm/libsql";
import { createClient } from "@libsql/client";
import { sqliteTable, text, integer, primaryKey } from "drizzle-orm/sqlite-core";
import { r as route } from "./ROUTES.js";
const dev = DEV;
var __classPrivateFieldSet = function(receiver, state2, value, kind, f2) {
  if (kind === "m")
    throw new TypeError("Private method is not writable");
  if (kind === "a" && !f2)
    throw new TypeError("Private accessor was defined without a setter");
  if (typeof state2 === "function" ? receiver !== state2 || !f2 : !state2.has(receiver))
    throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return kind === "a" ? f2.call(receiver, value) : f2 ? f2.value = value : state2.set(receiver, value), value;
};
var __classPrivateFieldGet = function(receiver, state2, kind, f2) {
  if (kind === "a" && !f2)
    throw new TypeError("Private accessor was defined without a getter");
  if (typeof state2 === "function" ? receiver !== state2 || !f2 : !state2.has(receiver))
    throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return kind === "m" ? f2 : kind === "a" ? f2.call(receiver) : f2 ? f2.value : state2.get(receiver);
};
var _SessionStore_instances, _SessionStore_chunks, _SessionStore_option, _SessionStore_logger, _SessionStore_chunk, _SessionStore_clean;
const ALLOWED_COOKIE_SIZE = 4096;
const ESTIMATED_EMPTY_COOKIE_SIZE = 160;
const CHUNK_SIZE$1 = ALLOWED_COOKIE_SIZE - ESTIMATED_EMPTY_COOKIE_SIZE;
function defaultCookies(useSecureCookies) {
  const cookiePrefix = useSecureCookies ? "__Secure-" : "";
  return {
    // default cookie options
    sessionToken: {
      name: `${cookiePrefix}authjs.session-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies
      }
    },
    callbackUrl: {
      name: `${cookiePrefix}authjs.callback-url`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies
      }
    },
    csrfToken: {
      // Default to __Host- for CSRF token for additional protection if using useSecureCookies
      // NB: The `__Host-` prefix is stricter than the `__Secure-` prefix.
      name: `${useSecureCookies ? "__Host-" : ""}authjs.csrf-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies
      }
    },
    pkceCodeVerifier: {
      name: `${cookiePrefix}authjs.pkce.code_verifier`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: 60 * 15
        // 15 minutes in seconds
      }
    },
    state: {
      name: `${cookiePrefix}authjs.state`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: 60 * 15
        // 15 minutes in seconds
      }
    },
    nonce: {
      name: `${cookiePrefix}authjs.nonce`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies
      }
    },
    webauthnChallenge: {
      name: `${cookiePrefix}authjs.challenge`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: 60 * 15
        // 15 minutes in seconds
      }
    }
  };
}
class SessionStore {
  constructor(option, cookies, logger2) {
    _SessionStore_instances.add(this);
    _SessionStore_chunks.set(this, {});
    _SessionStore_option.set(this, void 0);
    _SessionStore_logger.set(this, void 0);
    __classPrivateFieldSet(this, _SessionStore_logger, logger2, "f");
    __classPrivateFieldSet(this, _SessionStore_option, option, "f");
    if (!cookies)
      return;
    const { name: sessionCookiePrefix } = option;
    for (const [name, value] of Object.entries(cookies)) {
      if (!name.startsWith(sessionCookiePrefix) || !value)
        continue;
      __classPrivateFieldGet(this, _SessionStore_chunks, "f")[name] = value;
    }
  }
  /**
   * The JWT Session or database Session ID
   * constructed from the cookie chunks.
   */
  get value() {
    const sortedKeys = Object.keys(__classPrivateFieldGet(this, _SessionStore_chunks, "f")).sort((a2, b2) => {
      const aSuffix = parseInt(a2.split(".").pop() || "0");
      const bSuffix = parseInt(b2.split(".").pop() || "0");
      return aSuffix - bSuffix;
    });
    return sortedKeys.map((key) => __classPrivateFieldGet(this, _SessionStore_chunks, "f")[key]).join("");
  }
  /**
   * Given a cookie value, return new cookies, chunked, to fit the allowed cookie size.
   * If the cookie has changed from chunked to unchunked or vice versa,
   * it deletes the old cookies as well.
   */
  chunk(value, options) {
    const cookies = __classPrivateFieldGet(this, _SessionStore_instances, "m", _SessionStore_clean).call(this);
    const chunked = __classPrivateFieldGet(this, _SessionStore_instances, "m", _SessionStore_chunk).call(this, {
      name: __classPrivateFieldGet(this, _SessionStore_option, "f").name,
      value,
      options: { ...__classPrivateFieldGet(this, _SessionStore_option, "f").options, ...options }
    });
    for (const chunk of chunked) {
      cookies[chunk.name] = chunk;
    }
    return Object.values(cookies);
  }
  /** Returns a list of cookies that should be cleaned. */
  clean() {
    return Object.values(__classPrivateFieldGet(this, _SessionStore_instances, "m", _SessionStore_clean).call(this));
  }
}
_SessionStore_chunks = /* @__PURE__ */ new WeakMap(), _SessionStore_option = /* @__PURE__ */ new WeakMap(), _SessionStore_logger = /* @__PURE__ */ new WeakMap(), _SessionStore_instances = /* @__PURE__ */ new WeakSet(), _SessionStore_chunk = function _SessionStore_chunk2(cookie) {
  const chunkCount = Math.ceil(cookie.value.length / CHUNK_SIZE$1);
  if (chunkCount === 1) {
    __classPrivateFieldGet(this, _SessionStore_chunks, "f")[cookie.name] = cookie.value;
    return [cookie];
  }
  const cookies = [];
  for (let i2 = 0; i2 < chunkCount; i2++) {
    const name = `${cookie.name}.${i2}`;
    const value = cookie.value.substr(i2 * CHUNK_SIZE$1, CHUNK_SIZE$1);
    cookies.push({ ...cookie, name, value });
    __classPrivateFieldGet(this, _SessionStore_chunks, "f")[name] = value;
  }
  __classPrivateFieldGet(this, _SessionStore_logger, "f").debug("CHUNKING_SESSION_COOKIE", {
    message: `Session cookie exceeds allowed ${ALLOWED_COOKIE_SIZE} bytes.`,
    emptyCookieSize: ESTIMATED_EMPTY_COOKIE_SIZE,
    valueSize: cookie.value.length,
    chunks: cookies.map((c2) => c2.value.length + ESTIMATED_EMPTY_COOKIE_SIZE)
  });
  return cookies;
}, _SessionStore_clean = function _SessionStore_clean2() {
  const cleanedChunks = {};
  for (const name in __classPrivateFieldGet(this, _SessionStore_chunks, "f")) {
    delete __classPrivateFieldGet(this, _SessionStore_chunks, "f")?.[name];
    cleanedChunks[name] = {
      name,
      value: "",
      options: { ...__classPrivateFieldGet(this, _SessionStore_option, "f").options, maxAge: 0 }
    };
  }
  return cleanedChunks;
};
class AuthError extends Error {
  constructor(message2, errorOptions) {
    if (message2 instanceof Error) {
      super(void 0, {
        cause: { err: message2, ...message2.cause, ...errorOptions }
      });
    } else if (typeof message2 === "string") {
      if (errorOptions instanceof Error) {
        errorOptions = { err: errorOptions, ...errorOptions.cause };
      }
      super(message2, errorOptions);
    } else {
      super(void 0, message2);
    }
    this.name = this.constructor.name;
    this.type = this.constructor.type ?? "AuthError";
    this.kind = this.constructor.kind ?? "error";
    Error.captureStackTrace?.(this, this.constructor);
    const url = `https://errors.authjs.dev#${this.type.toLowerCase()}`;
    this.message += `${this.message ? " ." : ""}Read more at ${url}`;
  }
}
class SignInError extends AuthError {
}
SignInError.kind = "signIn";
class AdapterError extends AuthError {
}
AdapterError.type = "AdapterError";
class AccessDenied extends AuthError {
}
AccessDenied.type = "AccessDenied";
class CallbackRouteError extends AuthError {
}
CallbackRouteError.type = "CallbackRouteError";
class ErrorPageLoop extends AuthError {
}
ErrorPageLoop.type = "ErrorPageLoop";
class EventError extends AuthError {
}
EventError.type = "EventError";
class InvalidCallbackUrl extends AuthError {
}
InvalidCallbackUrl.type = "InvalidCallbackUrl";
class CredentialsSignin extends SignInError {
  constructor() {
    super(...arguments);
    this.code = "credentials";
  }
}
CredentialsSignin.type = "CredentialsSignin";
class InvalidEndpoints extends AuthError {
}
InvalidEndpoints.type = "InvalidEndpoints";
class InvalidCheck extends AuthError {
}
InvalidCheck.type = "InvalidCheck";
class JWTSessionError extends AuthError {
}
JWTSessionError.type = "JWTSessionError";
class MissingAdapter extends AuthError {
}
MissingAdapter.type = "MissingAdapter";
class MissingAdapterMethods extends AuthError {
}
MissingAdapterMethods.type = "MissingAdapterMethods";
class MissingAuthorize extends AuthError {
}
MissingAuthorize.type = "MissingAuthorize";
class MissingSecret extends AuthError {
}
MissingSecret.type = "MissingSecret";
class OAuthAccountNotLinked extends SignInError {
}
OAuthAccountNotLinked.type = "OAuthAccountNotLinked";
class OAuthCallbackError extends SignInError {
}
OAuthCallbackError.type = "OAuthCallbackError";
class OAuthProfileParseError extends AuthError {
}
OAuthProfileParseError.type = "OAuthProfileParseError";
class SessionTokenError extends AuthError {
}
SessionTokenError.type = "SessionTokenError";
class OAuthSignInError extends SignInError {
}
OAuthSignInError.type = "OAuthSignInError";
class EmailSignInError extends SignInError {
}
EmailSignInError.type = "EmailSignInError";
class SignOutError extends AuthError {
}
SignOutError.type = "SignOutError";
class UnknownAction extends AuthError {
}
UnknownAction.type = "UnknownAction";
class UnsupportedStrategy extends AuthError {
}
UnsupportedStrategy.type = "UnsupportedStrategy";
class InvalidProvider extends AuthError {
}
InvalidProvider.type = "InvalidProvider";
class UntrustedHost extends AuthError {
}
UntrustedHost.type = "UntrustedHost";
class Verification extends AuthError {
}
Verification.type = "Verification";
class MissingCSRF extends SignInError {
}
MissingCSRF.type = "MissingCSRF";
const clientErrors = /* @__PURE__ */ new Set([
  "CredentialsSignin",
  "OAuthAccountNotLinked",
  "OAuthCallbackError",
  "AccessDenied",
  "Verification",
  "MissingCSRF",
  "AccountNotLinked",
  "WebAuthnVerificationError"
]);
function isClientError(error) {
  if (error instanceof AuthError)
    return clientErrors.has(error.type);
  return false;
}
class DuplicateConditionalUI extends AuthError {
}
DuplicateConditionalUI.type = "DuplicateConditionalUI";
class MissingWebAuthnAutocomplete extends AuthError {
}
MissingWebAuthnAutocomplete.type = "MissingWebAuthnAutocomplete";
class WebAuthnVerificationError extends AuthError {
}
WebAuthnVerificationError.type = "WebAuthnVerificationError";
class AccountNotLinked extends SignInError {
}
AccountNotLinked.type = "AccountNotLinked";
class ExperimentalFeatureNotEnabled extends AuthError {
}
ExperimentalFeatureNotEnabled.type = "ExperimentalFeatureNotEnabled";
let warned = false;
function isValidHttpUrl(url, baseUrl) {
  try {
    return /^https?:/.test(new URL(url, url.startsWith("/") ? baseUrl : void 0).protocol);
  } catch {
    return false;
  }
}
function isSemverString(version) {
  return /^v\d+(?:\.\d+){0,2}$/.test(version);
}
let hasCredentials = false;
let hasEmail = false;
let hasWebAuthn = false;
const emailMethods = [
  "createVerificationToken",
  "useVerificationToken",
  "getUserByEmail"
];
const sessionMethods = [
  "createUser",
  "getUser",
  "getUserByEmail",
  "getUserByAccount",
  "updateUser",
  "linkAccount",
  "createSession",
  "getSessionAndUser",
  "updateSession",
  "deleteSession"
];
const webauthnMethods = [
  "createUser",
  "getUser",
  "linkAccount",
  "getAccount",
  "getAuthenticator",
  "createAuthenticator",
  "listAuthenticatorsByUserId",
  "updateAuthenticatorCounter"
];
function assertConfig(request, options) {
  const { url } = request;
  const warnings = [];
  if (!warned && options.debug)
    warnings.push("debug-enabled");
  if (!options.trustHost) {
    return new UntrustedHost(`Host must be trusted. URL was: ${request.url}`);
  }
  if (!options.secret) {
    return new MissingSecret("Please define a `secret`.");
  }
  const callbackUrlParam = request.query?.callbackUrl;
  if (callbackUrlParam && !isValidHttpUrl(callbackUrlParam, url.origin)) {
    return new InvalidCallbackUrl(`Invalid callback URL. Received: ${callbackUrlParam}`);
  }
  const { callbackUrl: defaultCallbackUrl } = defaultCookies(options.useSecureCookies ?? url.protocol === "https:");
  const callbackUrlCookie = request.cookies?.[options.cookies?.callbackUrl?.name ?? defaultCallbackUrl.name];
  if (callbackUrlCookie && !isValidHttpUrl(callbackUrlCookie, url.origin)) {
    return new InvalidCallbackUrl(`Invalid callback URL. Received: ${callbackUrlCookie}`);
  }
  let hasConditionalUIProvider = false;
  for (const p2 of options.providers) {
    const provider = typeof p2 === "function" ? p2() : p2;
    if ((provider.type === "oauth" || provider.type === "oidc") && !(provider.issuer ?? provider.options?.issuer)) {
      const { authorization: a2, token: t, userinfo: u2 } = provider;
      let key;
      if (typeof a2 !== "string" && !a2?.url)
        key = "authorization";
      else if (typeof t !== "string" && !t?.url)
        key = "token";
      else if (typeof u2 !== "string" && !u2?.url)
        key = "userinfo";
      if (key) {
        return new InvalidEndpoints(`Provider "${provider.id}" is missing both \`issuer\` and \`${key}\` endpoint config. At least one of them is required.`);
      }
    }
    if (provider.type === "credentials")
      hasCredentials = true;
    else if (provider.type === "email")
      hasEmail = true;
    else if (provider.type === "webauthn") {
      hasWebAuthn = true;
      if (provider.simpleWebAuthnBrowserVersion && !isSemverString(provider.simpleWebAuthnBrowserVersion)) {
        return new AuthError(`Invalid provider config for "${provider.id}": simpleWebAuthnBrowserVersion "${provider.simpleWebAuthnBrowserVersion}" must be a valid semver string.`);
      }
      if (provider.enableConditionalUI) {
        if (hasConditionalUIProvider) {
          return new DuplicateConditionalUI(`Multiple webauthn providers have 'enableConditionalUI' set to True. Only one provider can have this option enabled at a time.`);
        }
        hasConditionalUIProvider = true;
        const hasWebauthnFormField = Object.values(provider.formFields).some((f2) => f2.autocomplete && f2.autocomplete.toString().indexOf("webauthn") > -1);
        if (!hasWebauthnFormField) {
          return new MissingWebAuthnAutocomplete(`Provider "${provider.id}" has 'enableConditionalUI' set to True, but none of its formFields have 'webauthn' in their autocomplete param.`);
        }
      }
    }
  }
  if (hasCredentials) {
    const dbStrategy = options.session?.strategy === "database";
    const onlyCredentials = !options.providers.some((p2) => (typeof p2 === "function" ? p2() : p2).type !== "credentials");
    if (dbStrategy && onlyCredentials) {
      return new UnsupportedStrategy("Signing in with credentials only supported if JWT strategy is enabled");
    }
    const credentialsNoAuthorize = options.providers.some((p2) => {
      const provider = typeof p2 === "function" ? p2() : p2;
      return provider.type === "credentials" && !provider.authorize;
    });
    if (credentialsNoAuthorize) {
      return new MissingAuthorize("Must define an authorize() handler to use credentials authentication provider");
    }
  }
  const { adapter, session: session2 } = options;
  let requiredMethods = [];
  if (hasEmail || session2?.strategy === "database" || !session2?.strategy && adapter) {
    if (hasEmail) {
      if (!adapter)
        return new MissingAdapter("Email login requires an adapter.");
      requiredMethods.push(...emailMethods);
    } else {
      if (!adapter)
        return new MissingAdapter("Database session requires an adapter.");
      requiredMethods.push(...sessionMethods);
    }
  }
  if (hasWebAuthn) {
    if (options.experimental?.enableWebAuthn) {
      warnings.push("experimental-webauthn");
    } else {
      return new ExperimentalFeatureNotEnabled("WebAuthn is an experimental feature. To enable it, set `experimental.enableWebAuthn` to `true` in your config.");
    }
    if (!adapter)
      return new MissingAdapter("WebAuthn requires an adapter.");
    requiredMethods.push(...webauthnMethods);
  }
  if (adapter) {
    const missing = requiredMethods.filter((m2) => !(m2 in adapter));
    if (missing.length) {
      return new MissingAdapterMethods(`Required adapter methods were missing: ${missing.join(", ")}`);
    }
  }
  if (!warned)
    warned = true;
  return warnings;
}
const fallback = (digest2, ikm, salt, info, keylen) => {
  const hashlen = parseInt(digest2.substr(3), 10) >> 3 || 20;
  const prk = createHmac(digest2, salt.byteLength ? salt : new Uint8Array(hashlen)).update(ikm).digest();
  const N = Math.ceil(keylen / hashlen);
  const T = new Uint8Array(hashlen * N + info.byteLength + 1);
  let prev = 0;
  let start = 0;
  for (let c2 = 1; c2 <= N; c2++) {
    T.set(info, start);
    T[start + info.byteLength] = c2;
    T.set(createHmac(digest2, prk).update(T.subarray(prev, start + info.byteLength + 1)).digest(), start);
    prev = start;
    start += hashlen;
  }
  return T.slice(0, keylen);
};
let hkdf$1;
if (typeof crypto$1.hkdf === "function" && !process.versions.electron) {
  hkdf$1 = async (...args) => new Promise((resolve, reject) => {
    crypto$1.hkdf(...args, (err, arrayBuffer) => {
      if (err)
        reject(err);
      else
        resolve(new Uint8Array(arrayBuffer));
    });
  });
}
const derive = async (digest2, ikm, salt, info, keylen) => (hkdf$1 || fallback)(digest2, ikm, salt, info, keylen);
function normalizeDigest(digest2) {
  switch (digest2) {
    case "sha256":
    case "sha384":
    case "sha512":
    case "sha1":
      return digest2;
    default:
      throw new TypeError('unsupported "digest" value');
  }
}
function normalizeUint8Array(input, label) {
  if (typeof input === "string")
    return new TextEncoder().encode(input);
  if (!(input instanceof Uint8Array))
    throw new TypeError(`"${label}"" must be an instance of Uint8Array or a string`);
  return input;
}
function normalizeIkm(input) {
  const ikm = normalizeUint8Array(input, "ikm");
  if (!ikm.byteLength)
    throw new TypeError(`"ikm" must be at least one byte in length`);
  return ikm;
}
function normalizeInfo(input) {
  const info = normalizeUint8Array(input, "info");
  if (info.byteLength > 1024) {
    throw TypeError('"info" must not contain more than 1024 bytes');
  }
  return info;
}
function normalizeKeylen(input, digest2) {
  if (typeof input !== "number" || !Number.isInteger(input) || input < 1) {
    throw new TypeError('"keylen" must be a positive integer');
  }
  const hashlen = parseInt(digest2.substr(3), 10) >> 3 || 20;
  if (input > 255 * hashlen) {
    throw new TypeError('"keylen" too large');
  }
  return input;
}
async function hkdf(digest2, ikm, salt, info, keylen) {
  return derive(normalizeDigest(digest2), normalizeIkm(ikm), normalizeUint8Array(salt, "salt"), normalizeInfo(info), normalizeKeylen(keylen, digest2));
}
const digest = (algorithm, data) => createHash$1(algorithm).update(data).digest();
const encoder$1 = new TextEncoder();
const decoder$1 = new TextDecoder();
const MAX_INT32 = 2 ** 32;
function concat(...buffers) {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf2 = new Uint8Array(size);
  let i2 = 0;
  for (const buffer of buffers) {
    buf2.set(buffer, i2);
    i2 += buffer.length;
  }
  return buf2;
}
function p2s(alg2, p2sInput) {
  return concat(encoder$1.encode(alg2), new Uint8Array([0]), p2sInput);
}
function writeUInt32BE(buf2, value, offset) {
  if (value < 0 || value >= MAX_INT32) {
    throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`);
  }
  buf2.set([value >>> 24, value >>> 16, value >>> 8, value & 255], offset);
}
function uint64be(value) {
  const high = Math.floor(value / MAX_INT32);
  const low = value % MAX_INT32;
  const buf2 = new Uint8Array(8);
  writeUInt32BE(buf2, high, 0);
  writeUInt32BE(buf2, low, 4);
  return buf2;
}
function uint32be(value) {
  const buf2 = new Uint8Array(4);
  writeUInt32BE(buf2, value);
  return buf2;
}
function lengthAndInput(input) {
  return concat(uint32be(input.length), input);
}
async function concatKdf(secret, bits, value) {
  const iterations = Math.ceil((bits >> 3) / 32);
  const res = new Uint8Array(iterations * 32);
  for (let iter = 0; iter < iterations; iter++) {
    const buf2 = new Uint8Array(4 + secret.length + value.length);
    buf2.set(uint32be(iter + 1));
    buf2.set(secret, 4);
    buf2.set(value, 4 + secret.length);
    res.set(await digest("sha256", buf2), iter * 32);
  }
  return res.slice(0, bits >> 3);
}
function normalize(input) {
  let encoded = input;
  if (encoded instanceof Uint8Array) {
    encoded = decoder$1.decode(encoded);
  }
  return encoded;
}
const encode$2 = (input) => Buffer$1.from(input).toString("base64url");
const decode$2 = (input) => new Uint8Array(Buffer$1.from(normalize(input), "base64"));
class JOSEError extends Error {
  static get code() {
    return "ERR_JOSE_GENERIC";
  }
  code = "ERR_JOSE_GENERIC";
  constructor(message2) {
    super(message2);
    this.name = this.constructor.name;
    Error.captureStackTrace?.(this, this.constructor);
  }
}
class JWTClaimValidationFailed extends JOSEError {
  static get code() {
    return "ERR_JWT_CLAIM_VALIDATION_FAILED";
  }
  code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
  claim;
  reason;
  constructor(message2, claim = "unspecified", reason = "unspecified") {
    super(message2);
    this.claim = claim;
    this.reason = reason;
  }
}
class JWTExpired extends JOSEError {
  static get code() {
    return "ERR_JWT_EXPIRED";
  }
  code = "ERR_JWT_EXPIRED";
  claim;
  reason;
  constructor(message2, claim = "unspecified", reason = "unspecified") {
    super(message2);
    this.claim = claim;
    this.reason = reason;
  }
}
class JOSEAlgNotAllowed extends JOSEError {
  static get code() {
    return "ERR_JOSE_ALG_NOT_ALLOWED";
  }
  code = "ERR_JOSE_ALG_NOT_ALLOWED";
}
class JOSENotSupported extends JOSEError {
  static get code() {
    return "ERR_JOSE_NOT_SUPPORTED";
  }
  code = "ERR_JOSE_NOT_SUPPORTED";
}
class JWEDecryptionFailed extends JOSEError {
  static get code() {
    return "ERR_JWE_DECRYPTION_FAILED";
  }
  code = "ERR_JWE_DECRYPTION_FAILED";
  message = "decryption operation failed";
}
class JWEInvalid extends JOSEError {
  static get code() {
    return "ERR_JWE_INVALID";
  }
  code = "ERR_JWE_INVALID";
}
class JWTInvalid extends JOSEError {
  static get code() {
    return "ERR_JWT_INVALID";
  }
  code = "ERR_JWT_INVALID";
}
class JWKInvalid extends JOSEError {
  static get code() {
    return "ERR_JWK_INVALID";
  }
  code = "ERR_JWK_INVALID";
}
function bitLength$1(alg2) {
  switch (alg2) {
    case "A128GCM":
    case "A128GCMKW":
    case "A192GCM":
    case "A192GCMKW":
    case "A256GCM":
    case "A256GCMKW":
      return 96;
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      return 128;
    default:
      throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg2}`);
  }
}
const generateIv = (alg2) => randomFillSync(new Uint8Array(bitLength$1(alg2) >> 3));
const checkIvLength = (enc2, iv) => {
  if (iv.length << 3 !== bitLength$1(enc2)) {
    throw new JWEInvalid("Invalid Initialization Vector length");
  }
};
const isKeyObject = (obj) => util.types.isKeyObject(obj);
const checkCekLength = (enc2, cek) => {
  let expected;
  switch (enc2) {
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      expected = parseInt(enc2.slice(-3), 10);
      break;
    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
      expected = parseInt(enc2.slice(1, 4), 10);
      break;
    default:
      throw new JOSENotSupported(`Content Encryption Algorithm ${enc2} is not supported either by JOSE or your javascript runtime`);
  }
  if (cek instanceof Uint8Array) {
    const actual = cek.byteLength << 3;
    if (actual !== expected) {
      throw new JWEInvalid(`Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`);
    }
    return;
  }
  if (isKeyObject(cek) && cek.type === "secret") {
    const actual = cek.symmetricKeySize << 3;
    if (actual !== expected) {
      throw new JWEInvalid(`Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`);
    }
    return;
  }
  throw new TypeError("Invalid Content Encryption Key type");
};
const timingSafeEqual = timingSafeEqual$1;
function cbcTag(aad, iv, ciphertext, macSize, macKey, keySize) {
  const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
  const hmac = createHmac$1(`sha${macSize}`, macKey);
  hmac.update(macData);
  return hmac.digest().slice(0, keySize >> 3);
}
const webcrypto = crypto$2.webcrypto;
const isCryptoKey$1 = (key) => util.types.isCryptoKey(key);
function unusable(name, prop = "algorithm.name") {
  return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}
function isAlgorithm(algorithm, name) {
  return algorithm.name === name;
}
function getHashLength(hash) {
  return parseInt(hash.name.slice(4), 10);
}
function checkUsage(key, usages) {
  if (usages.length && !usages.some((expected) => key.usages.includes(expected))) {
    let msg = "CryptoKey does not support this operation, its usages must include ";
    if (usages.length > 2) {
      const last = usages.pop();
      msg += `one of ${usages.join(", ")}, or ${last}.`;
    } else if (usages.length === 2) {
      msg += `one of ${usages[0]} or ${usages[1]}.`;
    } else {
      msg += `${usages[0]}.`;
    }
    throw new TypeError(msg);
  }
}
function checkEncCryptoKey(key, alg2, ...usages) {
  switch (alg2) {
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      if (!isAlgorithm(key.algorithm, "AES-GCM"))
        throw unusable("AES-GCM");
      const expected = parseInt(alg2.slice(1, 4), 10);
      const actual = key.algorithm.length;
      if (actual !== expected)
        throw unusable(expected, "algorithm.length");
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      if (!isAlgorithm(key.algorithm, "AES-KW"))
        throw unusable("AES-KW");
      const expected = parseInt(alg2.slice(1, 4), 10);
      const actual = key.algorithm.length;
      if (actual !== expected)
        throw unusable(expected, "algorithm.length");
      break;
    }
    case "ECDH": {
      switch (key.algorithm.name) {
        case "ECDH":
        case "X25519":
        case "X448":
          break;
        default:
          throw unusable("ECDH, X25519, or X448");
      }
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW":
      if (!isAlgorithm(key.algorithm, "PBKDF2"))
        throw unusable("PBKDF2");
      break;
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      if (!isAlgorithm(key.algorithm, "RSA-OAEP"))
        throw unusable("RSA-OAEP");
      const expected = parseInt(alg2.slice(9), 10) || 1;
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    default:
      throw new TypeError("CryptoKey does not support this operation");
  }
  checkUsage(key, usages);
}
function message(msg, actual, ...types2) {
  if (types2.length > 2) {
    const last = types2.pop();
    msg += `one of type ${types2.join(", ")}, or ${last}.`;
  } else if (types2.length === 2) {
    msg += `one of type ${types2[0]} or ${types2[1]}.`;
  } else {
    msg += `of type ${types2[0]}.`;
  }
  if (actual == null) {
    msg += ` Received ${actual}`;
  } else if (typeof actual === "function" && actual.name) {
    msg += ` Received function ${actual.name}`;
  } else if (typeof actual === "object" && actual != null) {
    if (actual.constructor?.name) {
      msg += ` Received an instance of ${actual.constructor.name}`;
    }
  }
  return msg;
}
const invalidKeyInput = (actual, ...types2) => {
  return message("Key must be ", actual, ...types2);
};
function withAlg(alg2, actual, ...types2) {
  return message(`Key for the ${alg2} algorithm must be `, actual, ...types2);
}
let ciphers;
const supported = (algorithm) => {
  ciphers ||= new Set(getCiphers());
  return ciphers.has(algorithm);
};
const isKeyLike = (key) => isKeyObject(key) || isCryptoKey$1(key);
const types = ["KeyObject"];
if (globalThis.CryptoKey || webcrypto?.CryptoKey) {
  types.push("CryptoKey");
}
function cbcDecrypt(enc2, cek, ciphertext, iv, tag, aad) {
  const keySize = parseInt(enc2.slice(1, 4), 10);
  if (isKeyObject(cek)) {
    cek = cek.export();
  }
  const encKey = cek.subarray(keySize >> 3);
  const macKey = cek.subarray(0, keySize >> 3);
  const macSize = parseInt(enc2.slice(-3), 10);
  const algorithm = `aes-${keySize}-cbc`;
  if (!supported(algorithm)) {
    throw new JOSENotSupported(`alg ${enc2} is not supported by your javascript runtime`);
  }
  const expectedTag = cbcTag(aad, iv, ciphertext, macSize, macKey, keySize);
  let macCheckPassed;
  try {
    macCheckPassed = timingSafeEqual(tag, expectedTag);
  } catch {
  }
  if (!macCheckPassed) {
    throw new JWEDecryptionFailed();
  }
  let plaintext;
  try {
    const decipher = createDecipheriv(algorithm, encKey, iv);
    plaintext = concat(decipher.update(ciphertext), decipher.final());
  } catch {
  }
  if (!plaintext) {
    throw new JWEDecryptionFailed();
  }
  return plaintext;
}
function gcmDecrypt(enc2, cek, ciphertext, iv, tag, aad) {
  const keySize = parseInt(enc2.slice(1, 4), 10);
  const algorithm = `aes-${keySize}-gcm`;
  if (!supported(algorithm)) {
    throw new JOSENotSupported(`alg ${enc2} is not supported by your javascript runtime`);
  }
  try {
    const decipher = createDecipheriv(algorithm, cek, iv, { authTagLength: 16 });
    decipher.setAuthTag(tag);
    if (aad.byteLength) {
      decipher.setAAD(aad, { plaintextLength: ciphertext.length });
    }
    const plaintext = decipher.update(ciphertext);
    decipher.final();
    return plaintext;
  } catch {
    throw new JWEDecryptionFailed();
  }
}
const decrypt$2 = (enc2, cek, ciphertext, iv, tag, aad) => {
  let key;
  if (isCryptoKey$1(cek)) {
    checkEncCryptoKey(cek, enc2, "decrypt");
    key = KeyObject.from(cek);
  } else if (cek instanceof Uint8Array || isKeyObject(cek)) {
    key = cek;
  } else {
    throw new TypeError(invalidKeyInput(cek, ...types, "Uint8Array"));
  }
  if (!iv) {
    throw new JWEInvalid("JWE Initialization Vector missing");
  }
  if (!tag) {
    throw new JWEInvalid("JWE Authentication Tag missing");
  }
  checkCekLength(enc2, key);
  checkIvLength(enc2, iv);
  switch (enc2) {
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      return cbcDecrypt(enc2, key, ciphertext, iv, tag, aad);
    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
      return gcmDecrypt(enc2, key, ciphertext, iv, tag, aad);
    default:
      throw new JOSENotSupported("Unsupported JWE Content Encryption Algorithm");
  }
};
const isDisjoint = (...headers) => {
  const sources = headers.filter(Boolean);
  if (sources.length === 0 || sources.length === 1) {
    return true;
  }
  let acc;
  for (const header of sources) {
    const parameters = Object.keys(header);
    if (!acc || acc.size === 0) {
      acc = new Set(parameters);
      continue;
    }
    for (const parameter of parameters) {
      if (acc.has(parameter)) {
        return false;
      }
      acc.add(parameter);
    }
  }
  return true;
};
function isObjectLike(value) {
  return typeof value === "object" && value !== null;
}
function isObject$1(input) {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== "[object Object]") {
    return false;
  }
  if (Object.getPrototypeOf(input) === null) {
    return true;
  }
  let proto = input;
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(input) === proto;
}
function checkKeySize(key, alg2) {
  if (key.symmetricKeySize << 3 !== parseInt(alg2.slice(1, 4), 10)) {
    throw new TypeError(`Invalid key size for alg: ${alg2}`);
  }
}
function ensureKeyObject$1(key, alg2, usage) {
  if (isKeyObject(key)) {
    return key;
  }
  if (key instanceof Uint8Array) {
    return createSecretKey(key);
  }
  if (isCryptoKey$1(key)) {
    checkEncCryptoKey(key, alg2, usage);
    return KeyObject.from(key);
  }
  throw new TypeError(invalidKeyInput(key, ...types, "Uint8Array"));
}
const wrap$1 = (alg2, key, cek) => {
  const size = parseInt(alg2.slice(1, 4), 10);
  const algorithm = `aes${size}-wrap`;
  if (!supported(algorithm)) {
    throw new JOSENotSupported(`alg ${alg2} is not supported either by JOSE or your javascript runtime`);
  }
  const keyObject = ensureKeyObject$1(key, alg2, "wrapKey");
  checkKeySize(keyObject, alg2);
  const cipher = createCipheriv(algorithm, keyObject, Buffer$1.alloc(8, 166));
  return concat(cipher.update(cek), cipher.final());
};
const unwrap$1 = (alg2, key, encryptedKey) => {
  const size = parseInt(alg2.slice(1, 4), 10);
  const algorithm = `aes${size}-wrap`;
  if (!supported(algorithm)) {
    throw new JOSENotSupported(`alg ${alg2} is not supported either by JOSE or your javascript runtime`);
  }
  const keyObject = ensureKeyObject$1(key, alg2, "unwrapKey");
  checkKeySize(keyObject, alg2);
  const cipher = createDecipheriv(algorithm, keyObject, Buffer$1.alloc(8, 166));
  return concat(cipher.update(encryptedKey), cipher.final());
};
const namedCurveToJOSE = (namedCurve) => {
  switch (namedCurve) {
    case "prime256v1":
      return "P-256";
    case "secp384r1":
      return "P-384";
    case "secp521r1":
      return "P-521";
    case "secp256k1":
      return "secp256k1";
    default:
      throw new JOSENotSupported("Unsupported key curve for this operation");
  }
};
const getNamedCurve = (kee, raw2) => {
  let key;
  if (isCryptoKey$1(kee)) {
    key = KeyObject.from(kee);
  } else if (isKeyObject(kee)) {
    key = kee;
  } else {
    throw new TypeError(invalidKeyInput(kee, ...types));
  }
  if (key.type === "secret") {
    throw new TypeError('only "private" or "public" type keys can be used for this operation');
  }
  switch (key.asymmetricKeyType) {
    case "ed25519":
    case "ed448":
      return `Ed${key.asymmetricKeyType.slice(2)}`;
    case "x25519":
    case "x448":
      return `X${key.asymmetricKeyType.slice(1)}`;
    case "ec": {
      const namedCurve = key.asymmetricKeyDetails.namedCurve;
      if (raw2) {
        return namedCurve;
      }
      return namedCurveToJOSE(namedCurve);
    }
    default:
      throw new TypeError("Invalid asymmetric key type for this operation");
  }
};
const generateKeyPair = promisify(generateKeyPair$1);
async function deriveKey(publicKee, privateKee, algorithm, keyLength, apu = new Uint8Array(0), apv = new Uint8Array(0)) {
  let publicKey;
  if (isCryptoKey$1(publicKee)) {
    checkEncCryptoKey(publicKee, "ECDH");
    publicKey = KeyObject.from(publicKee);
  } else if (isKeyObject(publicKee)) {
    publicKey = publicKee;
  } else {
    throw new TypeError(invalidKeyInput(publicKee, ...types));
  }
  let privateKey;
  if (isCryptoKey$1(privateKee)) {
    checkEncCryptoKey(privateKee, "ECDH", "deriveBits");
    privateKey = KeyObject.from(privateKee);
  } else if (isKeyObject(privateKee)) {
    privateKey = privateKee;
  } else {
    throw new TypeError(invalidKeyInput(privateKee, ...types));
  }
  const value = concat(lengthAndInput(encoder$1.encode(algorithm)), lengthAndInput(apu), lengthAndInput(apv), uint32be(keyLength));
  const sharedSecret = diffieHellman({ privateKey, publicKey });
  return concatKdf(sharedSecret, keyLength, value);
}
async function generateEpk(kee) {
  let key;
  if (isCryptoKey$1(kee)) {
    key = KeyObject.from(kee);
  } else if (isKeyObject(kee)) {
    key = kee;
  } else {
    throw new TypeError(invalidKeyInput(kee, ...types));
  }
  switch (key.asymmetricKeyType) {
    case "x25519":
      return generateKeyPair("x25519");
    case "x448": {
      return generateKeyPair("x448");
    }
    case "ec": {
      const namedCurve = getNamedCurve(key);
      return generateKeyPair("ec", { namedCurve });
    }
    default:
      throw new JOSENotSupported("Invalid or unsupported EPK");
  }
}
const ecdhAllowed = (key) => ["P-256", "P-384", "P-521", "X25519", "X448"].includes(getNamedCurve(key));
function checkP2s(p2s2) {
  if (!(p2s2 instanceof Uint8Array) || p2s2.length < 8) {
    throw new JWEInvalid("PBES2 Salt Input must be 8 or more octets");
  }
}
const pbkdf2 = promisify(pbkdf2$1);
function getPassword(key, alg2) {
  if (isKeyObject(key)) {
    return key.export();
  }
  if (key instanceof Uint8Array) {
    return key;
  }
  if (isCryptoKey$1(key)) {
    checkEncCryptoKey(key, alg2, "deriveBits", "deriveKey");
    return KeyObject.from(key).export();
  }
  throw new TypeError(invalidKeyInput(key, ...types, "Uint8Array"));
}
const encrypt$2 = async (alg2, key, cek, p2c = 2048, p2s$1 = randomFillSync(new Uint8Array(16))) => {
  checkP2s(p2s$1);
  const salt = p2s(alg2, p2s$1);
  const keylen = parseInt(alg2.slice(13, 16), 10) >> 3;
  const password = getPassword(key, alg2);
  const derivedKey = await pbkdf2(password, salt, p2c, keylen, `sha${alg2.slice(8, 11)}`);
  const encryptedKey = await wrap$1(alg2.slice(-6), derivedKey, cek);
  return { encryptedKey, p2c, p2s: encode$2(p2s$1) };
};
const decrypt$1 = async (alg2, key, encryptedKey, p2c, p2s$1) => {
  checkP2s(p2s$1);
  const salt = p2s(alg2, p2s$1);
  const keylen = parseInt(alg2.slice(13, 16), 10) >> 3;
  const password = getPassword(key, alg2);
  const derivedKey = await pbkdf2(password, salt, p2c, keylen, `sha${alg2.slice(8, 11)}`);
  return unwrap$1(alg2.slice(-6), derivedKey, encryptedKey);
};
const checkKeyLength = (key, alg2) => {
  const { modulusLength } = key.asymmetricKeyDetails;
  if (typeof modulusLength !== "number" || modulusLength < 2048) {
    throw new TypeError(`${alg2} requires key modulusLength to be 2048 bits or larger`);
  }
};
const checkKey = (key, alg2) => {
  if (key.asymmetricKeyType !== "rsa") {
    throw new TypeError("Invalid key for this operation, its asymmetricKeyType must be rsa");
  }
  checkKeyLength(key, alg2);
};
const RSA1_5 = deprecate(() => constants.RSA_PKCS1_PADDING, 'The RSA1_5 "alg" (JWE Algorithm) is deprecated and will be removed in the next major revision.');
const resolvePadding = (alg2) => {
  switch (alg2) {
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512":
      return constants.RSA_PKCS1_OAEP_PADDING;
    case "RSA1_5":
      return RSA1_5();
    default:
      return void 0;
  }
};
const resolveOaepHash = (alg2) => {
  switch (alg2) {
    case "RSA-OAEP":
      return "sha1";
    case "RSA-OAEP-256":
      return "sha256";
    case "RSA-OAEP-384":
      return "sha384";
    case "RSA-OAEP-512":
      return "sha512";
    default:
      return void 0;
  }
};
function ensureKeyObject(key, alg2, ...usages) {
  if (isKeyObject(key)) {
    return key;
  }
  if (isCryptoKey$1(key)) {
    checkEncCryptoKey(key, alg2, ...usages);
    return KeyObject.from(key);
  }
  throw new TypeError(invalidKeyInput(key, ...types));
}
const encrypt$1 = (alg2, key, cek) => {
  const padding = resolvePadding(alg2);
  const oaepHash = resolveOaepHash(alg2);
  const keyObject = ensureKeyObject(key, alg2, "wrapKey", "encrypt");
  checkKey(keyObject, alg2);
  return publicEncrypt({ key: keyObject, oaepHash, padding }, cek);
};
const decrypt = (alg2, key, encryptedKey) => {
  const padding = resolvePadding(alg2);
  const oaepHash = resolveOaepHash(alg2);
  const keyObject = ensureKeyObject(key, alg2, "unwrapKey", "decrypt");
  checkKey(keyObject, alg2);
  return privateDecrypt({ key: keyObject, oaepHash, padding }, encryptedKey);
};
function bitLength(alg2) {
  switch (alg2) {
    case "A128GCM":
      return 128;
    case "A192GCM":
      return 192;
    case "A256GCM":
    case "A128CBC-HS256":
      return 256;
    case "A192CBC-HS384":
      return 384;
    case "A256CBC-HS512":
      return 512;
    default:
      throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg2}`);
  }
}
const generateCek = (alg2) => randomFillSync(new Uint8Array(bitLength(alg2) >> 3));
const parse = (jwk) => {
  return (jwk.d ? createPrivateKey : createPublicKey)({ format: "jwk", key: jwk });
};
async function importJWK(jwk, alg2) {
  if (!isObject$1(jwk)) {
    throw new TypeError("JWK must be an object");
  }
  alg2 ||= jwk.alg;
  switch (jwk.kty) {
    case "oct":
      if (typeof jwk.k !== "string" || !jwk.k) {
        throw new TypeError('missing "k" (Key Value) Parameter value');
      }
      return decode$2(jwk.k);
    case "RSA":
      if (jwk.oth !== void 0) {
        throw new JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
      }
    case "EC":
    case "OKP":
      return parse({ ...jwk, alg: alg2 });
    default:
      throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
  }
}
const symmetricTypeCheck = (alg2, key) => {
  if (key instanceof Uint8Array)
    return;
  if (!isKeyLike(key)) {
    throw new TypeError(withAlg(alg2, key, ...types, "Uint8Array"));
  }
  if (key.type !== "secret") {
    throw new TypeError(`${types.join(" or ")} instances for symmetric algorithms must be of type "secret"`);
  }
};
const asymmetricTypeCheck = (alg2, key, usage) => {
  if (!isKeyLike(key)) {
    throw new TypeError(withAlg(alg2, key, ...types));
  }
  if (key.type === "secret") {
    throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithms must not be of type "secret"`);
  }
  if (usage === "sign" && key.type === "public") {
    throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm signing must be of type "private"`);
  }
  if (usage === "decrypt" && key.type === "public") {
    throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm decryption must be of type "private"`);
  }
  if (key.algorithm && usage === "verify" && key.type === "private") {
    throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm verifying must be of type "public"`);
  }
  if (key.algorithm && usage === "encrypt" && key.type === "private") {
    throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm encryption must be of type "public"`);
  }
};
const checkKeyType = (alg2, key, usage) => {
  const symmetric = alg2.startsWith("HS") || alg2 === "dir" || alg2.startsWith("PBES2") || /^A\d{3}(?:GCM)?KW$/.test(alg2);
  if (symmetric) {
    symmetricTypeCheck(alg2, key);
  } else {
    asymmetricTypeCheck(alg2, key, usage);
  }
};
function cbcEncrypt(enc2, plaintext, cek, iv, aad) {
  const keySize = parseInt(enc2.slice(1, 4), 10);
  if (isKeyObject(cek)) {
    cek = cek.export();
  }
  const encKey = cek.subarray(keySize >> 3);
  const macKey = cek.subarray(0, keySize >> 3);
  const algorithm = `aes-${keySize}-cbc`;
  if (!supported(algorithm)) {
    throw new JOSENotSupported(`alg ${enc2} is not supported by your javascript runtime`);
  }
  const cipher = createCipheriv(algorithm, encKey, iv);
  const ciphertext = concat(cipher.update(plaintext), cipher.final());
  const macSize = parseInt(enc2.slice(-3), 10);
  const tag = cbcTag(aad, iv, ciphertext, macSize, macKey, keySize);
  return { ciphertext, tag, iv };
}
function gcmEncrypt(enc2, plaintext, cek, iv, aad) {
  const keySize = parseInt(enc2.slice(1, 4), 10);
  const algorithm = `aes-${keySize}-gcm`;
  if (!supported(algorithm)) {
    throw new JOSENotSupported(`alg ${enc2} is not supported by your javascript runtime`);
  }
  const cipher = createCipheriv(algorithm, cek, iv, { authTagLength: 16 });
  if (aad.byteLength) {
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
  }
  const ciphertext = cipher.update(plaintext);
  cipher.final();
  const tag = cipher.getAuthTag();
  return { ciphertext, tag, iv };
}
const encrypt = (enc2, plaintext, cek, iv, aad) => {
  let key;
  if (isCryptoKey$1(cek)) {
    checkEncCryptoKey(cek, enc2, "encrypt");
    key = KeyObject.from(cek);
  } else if (cek instanceof Uint8Array || isKeyObject(cek)) {
    key = cek;
  } else {
    throw new TypeError(invalidKeyInput(cek, ...types, "Uint8Array"));
  }
  checkCekLength(enc2, key);
  if (iv) {
    checkIvLength(enc2, iv);
  } else {
    iv = generateIv(enc2);
  }
  switch (enc2) {
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      return cbcEncrypt(enc2, plaintext, key, iv, aad);
    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
      return gcmEncrypt(enc2, plaintext, key, iv, aad);
    default:
      throw new JOSENotSupported("Unsupported JWE Content Encryption Algorithm");
  }
};
async function wrap(alg2, key, cek, iv) {
  const jweAlgorithm = alg2.slice(0, 7);
  const wrapped = await encrypt(jweAlgorithm, cek, key, iv, new Uint8Array(0));
  return {
    encryptedKey: wrapped.ciphertext,
    iv: encode$2(wrapped.iv),
    tag: encode$2(wrapped.tag)
  };
}
async function unwrap(alg2, key, encryptedKey, iv, tag) {
  const jweAlgorithm = alg2.slice(0, 7);
  return decrypt$2(jweAlgorithm, key, encryptedKey, iv, tag, new Uint8Array(0));
}
async function decryptKeyManagement(alg2, key, encryptedKey, joseHeader, options) {
  checkKeyType(alg2, key, "decrypt");
  switch (alg2) {
    case "dir": {
      if (encryptedKey !== void 0)
        throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
      return key;
    }
    case "ECDH-ES":
      if (encryptedKey !== void 0)
        throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!isObject$1(joseHeader.epk))
        throw new JWEInvalid(`JOSE Header "epk" (Ephemeral Public Key) missing or invalid`);
      if (!ecdhAllowed(key))
        throw new JOSENotSupported("ECDH with the provided key is not allowed or not supported by your javascript runtime");
      const epk = await importJWK(joseHeader.epk, alg2);
      let partyUInfo;
      let partyVInfo;
      if (joseHeader.apu !== void 0) {
        if (typeof joseHeader.apu !== "string")
          throw new JWEInvalid(`JOSE Header "apu" (Agreement PartyUInfo) invalid`);
        try {
          partyUInfo = decode$2(joseHeader.apu);
        } catch {
          throw new JWEInvalid("Failed to base64url decode the apu");
        }
      }
      if (joseHeader.apv !== void 0) {
        if (typeof joseHeader.apv !== "string")
          throw new JWEInvalid(`JOSE Header "apv" (Agreement PartyVInfo) invalid`);
        try {
          partyVInfo = decode$2(joseHeader.apv);
        } catch {
          throw new JWEInvalid("Failed to base64url decode the apv");
        }
      }
      const sharedSecret = await deriveKey(epk, key, alg2 === "ECDH-ES" ? joseHeader.enc : alg2, alg2 === "ECDH-ES" ? bitLength(joseHeader.enc) : parseInt(alg2.slice(-5, -2), 10), partyUInfo, partyVInfo);
      if (alg2 === "ECDH-ES")
        return sharedSecret;
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return unwrap$1(alg2.slice(-6), sharedSecret, encryptedKey);
    }
    case "RSA1_5":
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return decrypt(alg2, key, encryptedKey);
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      if (typeof joseHeader.p2c !== "number")
        throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) missing or invalid`);
      const p2cLimit = options?.maxPBES2Count || 1e4;
      if (joseHeader.p2c > p2cLimit)
        throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) out is of acceptable bounds`);
      if (typeof joseHeader.p2s !== "string")
        throw new JWEInvalid(`JOSE Header "p2s" (PBES2 Salt) missing or invalid`);
      let p2s2;
      try {
        p2s2 = decode$2(joseHeader.p2s);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the p2s");
      }
      return decrypt$1(alg2, key, encryptedKey, joseHeader.p2c, p2s2);
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return unwrap$1(alg2, key, encryptedKey);
    }
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      if (typeof joseHeader.iv !== "string")
        throw new JWEInvalid(`JOSE Header "iv" (Initialization Vector) missing or invalid`);
      if (typeof joseHeader.tag !== "string")
        throw new JWEInvalid(`JOSE Header "tag" (Authentication Tag) missing or invalid`);
      let iv;
      try {
        iv = decode$2(joseHeader.iv);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the iv");
      }
      let tag;
      try {
        tag = decode$2(joseHeader.tag);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the tag");
      }
      return unwrap(alg2, key, encryptedKey, iv, tag);
    }
    default: {
      throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
    }
  }
}
function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
  if (joseHeader.crit !== void 0 && protectedHeader?.crit === void 0) {
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  }
  if (!protectedHeader || protectedHeader.crit === void 0) {
    return /* @__PURE__ */ new Set();
  }
  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input !== "string" || input.length === 0)) {
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  }
  let recognized;
  if (recognizedOption !== void 0) {
    recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
  } else {
    recognized = recognizedDefault;
  }
  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    }
    if (joseHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    }
    if (recognized.get(parameter) && protectedHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
    }
  }
  return new Set(protectedHeader.crit);
}
const validateAlgorithms = (option, algorithms) => {
  if (algorithms !== void 0 && (!Array.isArray(algorithms) || algorithms.some((s2) => typeof s2 !== "string"))) {
    throw new TypeError(`"${option}" option must be an array of strings`);
  }
  if (!algorithms) {
    return void 0;
  }
  return new Set(algorithms);
};
async function flattenedDecrypt(jwe, key, options) {
  if (!isObject$1(jwe)) {
    throw new JWEInvalid("Flattened JWE must be an object");
  }
  if (jwe.protected === void 0 && jwe.header === void 0 && jwe.unprotected === void 0) {
    throw new JWEInvalid("JOSE Header missing");
  }
  if (jwe.iv !== void 0 && typeof jwe.iv !== "string") {
    throw new JWEInvalid("JWE Initialization Vector incorrect type");
  }
  if (typeof jwe.ciphertext !== "string") {
    throw new JWEInvalid("JWE Ciphertext missing or incorrect type");
  }
  if (jwe.tag !== void 0 && typeof jwe.tag !== "string") {
    throw new JWEInvalid("JWE Authentication Tag incorrect type");
  }
  if (jwe.protected !== void 0 && typeof jwe.protected !== "string") {
    throw new JWEInvalid("JWE Protected Header incorrect type");
  }
  if (jwe.encrypted_key !== void 0 && typeof jwe.encrypted_key !== "string") {
    throw new JWEInvalid("JWE Encrypted Key incorrect type");
  }
  if (jwe.aad !== void 0 && typeof jwe.aad !== "string") {
    throw new JWEInvalid("JWE AAD incorrect type");
  }
  if (jwe.header !== void 0 && !isObject$1(jwe.header)) {
    throw new JWEInvalid("JWE Shared Unprotected Header incorrect type");
  }
  if (jwe.unprotected !== void 0 && !isObject$1(jwe.unprotected)) {
    throw new JWEInvalid("JWE Per-Recipient Unprotected Header incorrect type");
  }
  let parsedProt;
  if (jwe.protected) {
    try {
      const protectedHeader2 = decode$2(jwe.protected);
      parsedProt = JSON.parse(decoder$1.decode(protectedHeader2));
    } catch {
      throw new JWEInvalid("JWE Protected Header is invalid");
    }
  }
  if (!isDisjoint(parsedProt, jwe.header, jwe.unprotected)) {
    throw new JWEInvalid("JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint");
  }
  const joseHeader = {
    ...parsedProt,
    ...jwe.header,
    ...jwe.unprotected
  };
  validateCrit(JWEInvalid, /* @__PURE__ */ new Map(), options?.crit, parsedProt, joseHeader);
  if (joseHeader.zip !== void 0) {
    throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
  }
  const { alg: alg2, enc: enc2 } = joseHeader;
  if (typeof alg2 !== "string" || !alg2) {
    throw new JWEInvalid("missing JWE Algorithm (alg) in JWE Header");
  }
  if (typeof enc2 !== "string" || !enc2) {
    throw new JWEInvalid("missing JWE Encryption Algorithm (enc) in JWE Header");
  }
  const keyManagementAlgorithms = options && validateAlgorithms("keyManagementAlgorithms", options.keyManagementAlgorithms);
  const contentEncryptionAlgorithms = options && validateAlgorithms("contentEncryptionAlgorithms", options.contentEncryptionAlgorithms);
  if (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg2) || !keyManagementAlgorithms && alg2.startsWith("PBES2")) {
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
  }
  if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc2)) {
    throw new JOSEAlgNotAllowed('"enc" (Encryption Algorithm) Header Parameter value not allowed');
  }
  let encryptedKey;
  if (jwe.encrypted_key !== void 0) {
    try {
      encryptedKey = decode$2(jwe.encrypted_key);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the encrypted_key");
    }
  }
  let resolvedKey = false;
  if (typeof key === "function") {
    key = await key(parsedProt, jwe);
    resolvedKey = true;
  }
  let cek;
  try {
    cek = await decryptKeyManagement(alg2, key, encryptedKey, joseHeader, options);
  } catch (err) {
    if (err instanceof TypeError || err instanceof JWEInvalid || err instanceof JOSENotSupported) {
      throw err;
    }
    cek = generateCek(enc2);
  }
  let iv;
  let tag;
  if (jwe.iv !== void 0) {
    try {
      iv = decode$2(jwe.iv);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the iv");
    }
  }
  if (jwe.tag !== void 0) {
    try {
      tag = decode$2(jwe.tag);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the tag");
    }
  }
  const protectedHeader = encoder$1.encode(jwe.protected ?? "");
  let additionalData;
  if (jwe.aad !== void 0) {
    additionalData = concat(protectedHeader, encoder$1.encode("."), encoder$1.encode(jwe.aad));
  } else {
    additionalData = protectedHeader;
  }
  let ciphertext;
  try {
    ciphertext = decode$2(jwe.ciphertext);
  } catch {
    throw new JWEInvalid("Failed to base64url decode the ciphertext");
  }
  const plaintext = await decrypt$2(enc2, cek, ciphertext, iv, tag, additionalData);
  const result = { plaintext };
  if (jwe.protected !== void 0) {
    result.protectedHeader = parsedProt;
  }
  if (jwe.aad !== void 0) {
    try {
      result.additionalAuthenticatedData = decode$2(jwe.aad);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the aad");
    }
  }
  if (jwe.unprotected !== void 0) {
    result.sharedUnprotectedHeader = jwe.unprotected;
  }
  if (jwe.header !== void 0) {
    result.unprotectedHeader = jwe.header;
  }
  if (resolvedKey) {
    return { ...result, key };
  }
  return result;
}
async function compactDecrypt(jwe, key, options) {
  if (jwe instanceof Uint8Array) {
    jwe = decoder$1.decode(jwe);
  }
  if (typeof jwe !== "string") {
    throw new JWEInvalid("Compact JWE must be a string or Uint8Array");
  }
  const { 0: protectedHeader, 1: encryptedKey, 2: iv, 3: ciphertext, 4: tag, length } = jwe.split(".");
  if (length !== 5) {
    throw new JWEInvalid("Invalid Compact JWE");
  }
  const decrypted = await flattenedDecrypt({
    ciphertext,
    iv: iv || void 0,
    protected: protectedHeader,
    tag: tag || void 0,
    encrypted_key: encryptedKey || void 0
  }, key, options);
  const result = { plaintext: decrypted.plaintext, protectedHeader: decrypted.protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: decrypted.key };
  }
  return result;
}
const keyToJWK = (key) => {
  let keyObject;
  if (isCryptoKey$1(key)) {
    if (!key.extractable) {
      throw new TypeError("CryptoKey is not extractable");
    }
    keyObject = KeyObject.from(key);
  } else if (isKeyObject(key)) {
    keyObject = key;
  } else if (key instanceof Uint8Array) {
    return {
      kty: "oct",
      k: encode$2(key)
    };
  } else {
    throw new TypeError(invalidKeyInput(key, ...types, "Uint8Array"));
  }
  if (keyObject.type !== "secret" && !["rsa", "ec", "ed25519", "x25519", "ed448", "x448"].includes(keyObject.asymmetricKeyType)) {
    throw new JOSENotSupported("Unsupported key asymmetricKeyType");
  }
  return keyObject.export({ format: "jwk" });
};
async function exportJWK(key) {
  return keyToJWK(key);
}
async function encryptKeyManagement(alg2, enc2, key, providedCek, providedParameters = {}) {
  let encryptedKey;
  let parameters;
  let cek;
  checkKeyType(alg2, key, "encrypt");
  switch (alg2) {
    case "dir": {
      cek = key;
      break;
    }
    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!ecdhAllowed(key)) {
        throw new JOSENotSupported("ECDH with the provided key is not allowed or not supported by your javascript runtime");
      }
      const { apu, apv } = providedParameters;
      let { epk: ephemeralKey } = providedParameters;
      ephemeralKey ||= (await generateEpk(key)).privateKey;
      const { x: x2, y: y2, crv, kty } = await exportJWK(ephemeralKey);
      const sharedSecret = await deriveKey(key, ephemeralKey, alg2 === "ECDH-ES" ? enc2 : alg2, alg2 === "ECDH-ES" ? bitLength(enc2) : parseInt(alg2.slice(-5, -2), 10), apu, apv);
      parameters = { epk: { x: x2, crv, kty } };
      if (kty === "EC")
        parameters.epk.y = y2;
      if (apu)
        parameters.apu = encode$2(apu);
      if (apv)
        parameters.apv = encode$2(apv);
      if (alg2 === "ECDH-ES") {
        cek = sharedSecret;
        break;
      }
      cek = providedCek || generateCek(enc2);
      const kwAlg = alg2.slice(-6);
      encryptedKey = await wrap$1(kwAlg, sharedSecret, cek);
      break;
    }
    case "RSA1_5":
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      cek = providedCek || generateCek(enc2);
      encryptedKey = await encrypt$1(alg2, key, cek);
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      cek = providedCek || generateCek(enc2);
      const { p2c, p2s: p2s2 } = providedParameters;
      ({ encryptedKey, ...parameters } = await encrypt$2(alg2, key, cek, p2c, p2s2));
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      cek = providedCek || generateCek(enc2);
      encryptedKey = await wrap$1(alg2, key, cek);
      break;
    }
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      cek = providedCek || generateCek(enc2);
      const { iv } = providedParameters;
      ({ encryptedKey, ...parameters } = await wrap(alg2, key, cek, iv));
      break;
    }
    default: {
      throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
    }
  }
  return { cek, encryptedKey, parameters };
}
const unprotected = Symbol();
class FlattenedEncrypt {
  _plaintext;
  _protectedHeader;
  _sharedUnprotectedHeader;
  _unprotectedHeader;
  _aad;
  _cek;
  _iv;
  _keyManagementParameters;
  constructor(plaintext) {
    if (!(plaintext instanceof Uint8Array)) {
      throw new TypeError("plaintext must be an instance of Uint8Array");
    }
    this._plaintext = plaintext;
  }
  setKeyManagementParameters(parameters) {
    if (this._keyManagementParameters) {
      throw new TypeError("setKeyManagementParameters can only be called once");
    }
    this._keyManagementParameters = parameters;
    return this;
  }
  setProtectedHeader(protectedHeader) {
    if (this._protectedHeader) {
      throw new TypeError("setProtectedHeader can only be called once");
    }
    this._protectedHeader = protectedHeader;
    return this;
  }
  setSharedUnprotectedHeader(sharedUnprotectedHeader) {
    if (this._sharedUnprotectedHeader) {
      throw new TypeError("setSharedUnprotectedHeader can only be called once");
    }
    this._sharedUnprotectedHeader = sharedUnprotectedHeader;
    return this;
  }
  setUnprotectedHeader(unprotectedHeader) {
    if (this._unprotectedHeader) {
      throw new TypeError("setUnprotectedHeader can only be called once");
    }
    this._unprotectedHeader = unprotectedHeader;
    return this;
  }
  setAdditionalAuthenticatedData(aad) {
    this._aad = aad;
    return this;
  }
  setContentEncryptionKey(cek) {
    if (this._cek) {
      throw new TypeError("setContentEncryptionKey can only be called once");
    }
    this._cek = cek;
    return this;
  }
  setInitializationVector(iv) {
    if (this._iv) {
      throw new TypeError("setInitializationVector can only be called once");
    }
    this._iv = iv;
    return this;
  }
  async encrypt(key, options) {
    if (!this._protectedHeader && !this._unprotectedHeader && !this._sharedUnprotectedHeader) {
      throw new JWEInvalid("either setProtectedHeader, setUnprotectedHeader, or sharedUnprotectedHeader must be called before #encrypt()");
    }
    if (!isDisjoint(this._protectedHeader, this._unprotectedHeader, this._sharedUnprotectedHeader)) {
      throw new JWEInvalid("JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint");
    }
    const joseHeader = {
      ...this._protectedHeader,
      ...this._unprotectedHeader,
      ...this._sharedUnprotectedHeader
    };
    validateCrit(JWEInvalid, /* @__PURE__ */ new Map(), options?.crit, this._protectedHeader, joseHeader);
    if (joseHeader.zip !== void 0) {
      throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
    }
    const { alg: alg2, enc: enc2 } = joseHeader;
    if (typeof alg2 !== "string" || !alg2) {
      throw new JWEInvalid('JWE "alg" (Algorithm) Header Parameter missing or invalid');
    }
    if (typeof enc2 !== "string" || !enc2) {
      throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
    }
    let encryptedKey;
    if (this._cek && (alg2 === "dir" || alg2 === "ECDH-ES")) {
      throw new TypeError(`setContentEncryptionKey cannot be called with JWE "alg" (Algorithm) Header ${alg2}`);
    }
    let cek;
    {
      let parameters;
      ({ cek, encryptedKey, parameters } = await encryptKeyManagement(alg2, enc2, key, this._cek, this._keyManagementParameters));
      if (parameters) {
        if (options && unprotected in options) {
          if (!this._unprotectedHeader) {
            this.setUnprotectedHeader(parameters);
          } else {
            this._unprotectedHeader = { ...this._unprotectedHeader, ...parameters };
          }
        } else {
          if (!this._protectedHeader) {
            this.setProtectedHeader(parameters);
          } else {
            this._protectedHeader = { ...this._protectedHeader, ...parameters };
          }
        }
      }
    }
    let additionalData;
    let protectedHeader;
    let aadMember;
    if (this._protectedHeader) {
      protectedHeader = encoder$1.encode(encode$2(JSON.stringify(this._protectedHeader)));
    } else {
      protectedHeader = encoder$1.encode("");
    }
    if (this._aad) {
      aadMember = encode$2(this._aad);
      additionalData = concat(protectedHeader, encoder$1.encode("."), encoder$1.encode(aadMember));
    } else {
      additionalData = protectedHeader;
    }
    const { ciphertext, tag, iv } = await encrypt(enc2, this._plaintext, cek, this._iv, additionalData);
    const jwe = {
      ciphertext: encode$2(ciphertext)
    };
    if (iv) {
      jwe.iv = encode$2(iv);
    }
    if (tag) {
      jwe.tag = encode$2(tag);
    }
    if (encryptedKey) {
      jwe.encrypted_key = encode$2(encryptedKey);
    }
    if (aadMember) {
      jwe.aad = aadMember;
    }
    if (this._protectedHeader) {
      jwe.protected = decoder$1.decode(protectedHeader);
    }
    if (this._sharedUnprotectedHeader) {
      jwe.unprotected = this._sharedUnprotectedHeader;
    }
    if (this._unprotectedHeader) {
      jwe.header = this._unprotectedHeader;
    }
    return jwe;
  }
}
const epoch = (date) => Math.floor(date.getTime() / 1e3);
const minute = 60;
const hour = minute * 60;
const day = hour * 24;
const week = day * 7;
const year = day * 365.25;
const REGEX = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i;
const secs = (str) => {
  const matched = REGEX.exec(str);
  if (!matched || matched[4] && matched[1]) {
    throw new TypeError("Invalid time period format");
  }
  const value = parseFloat(matched[2]);
  const unit = matched[3].toLowerCase();
  let numericDate;
  switch (unit) {
    case "sec":
    case "secs":
    case "second":
    case "seconds":
    case "s":
      numericDate = Math.round(value);
      break;
    case "minute":
    case "minutes":
    case "min":
    case "mins":
    case "m":
      numericDate = Math.round(value * minute);
      break;
    case "hour":
    case "hours":
    case "hr":
    case "hrs":
    case "h":
      numericDate = Math.round(value * hour);
      break;
    case "day":
    case "days":
    case "d":
      numericDate = Math.round(value * day);
      break;
    case "week":
    case "weeks":
    case "w":
      numericDate = Math.round(value * week);
      break;
    default:
      numericDate = Math.round(value * year);
      break;
  }
  if (matched[1] === "-" || matched[4] === "ago") {
    return -numericDate;
  }
  return numericDate;
};
const normalizeTyp = (value) => value.toLowerCase().replace(/^application\//, "");
const checkAudiencePresence = (audPayload, audOption) => {
  if (typeof audPayload === "string") {
    return audOption.includes(audPayload);
  }
  if (Array.isArray(audPayload)) {
    return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
  }
  return false;
};
const jwtPayload = (protectedHeader, encodedPayload, options = {}) => {
  const { typ } = options;
  if (typ && (typeof protectedHeader.typ !== "string" || normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))) {
    throw new JWTClaimValidationFailed('unexpected "typ" JWT header value', "typ", "check_failed");
  }
  let payload;
  try {
    payload = JSON.parse(decoder$1.decode(encodedPayload));
  } catch {
  }
  if (!isObject$1(payload)) {
    throw new JWTInvalid("JWT Claims Set must be a top-level JSON object");
  }
  const { requiredClaims = [], issuer, subject, audience, maxTokenAge } = options;
  const presenceCheck = [...requiredClaims];
  if (maxTokenAge !== void 0)
    presenceCheck.push("iat");
  if (audience !== void 0)
    presenceCheck.push("aud");
  if (subject !== void 0)
    presenceCheck.push("sub");
  if (issuer !== void 0)
    presenceCheck.push("iss");
  for (const claim of new Set(presenceCheck.reverse())) {
    if (!(claim in payload)) {
      throw new JWTClaimValidationFailed(`missing required "${claim}" claim`, claim, "missing");
    }
  }
  if (issuer && !(Array.isArray(issuer) ? issuer : [issuer]).includes(payload.iss)) {
    throw new JWTClaimValidationFailed('unexpected "iss" claim value', "iss", "check_failed");
  }
  if (subject && payload.sub !== subject) {
    throw new JWTClaimValidationFailed('unexpected "sub" claim value', "sub", "check_failed");
  }
  if (audience && !checkAudiencePresence(payload.aud, typeof audience === "string" ? [audience] : audience)) {
    throw new JWTClaimValidationFailed('unexpected "aud" claim value', "aud", "check_failed");
  }
  let tolerance;
  switch (typeof options.clockTolerance) {
    case "string":
      tolerance = secs(options.clockTolerance);
      break;
    case "number":
      tolerance = options.clockTolerance;
      break;
    case "undefined":
      tolerance = 0;
      break;
    default:
      throw new TypeError("Invalid clockTolerance option type");
  }
  const { currentDate } = options;
  const now2 = epoch(currentDate || /* @__PURE__ */ new Date());
  if ((payload.iat !== void 0 || maxTokenAge) && typeof payload.iat !== "number") {
    throw new JWTClaimValidationFailed('"iat" claim must be a number', "iat", "invalid");
  }
  if (payload.nbf !== void 0) {
    if (typeof payload.nbf !== "number") {
      throw new JWTClaimValidationFailed('"nbf" claim must be a number', "nbf", "invalid");
    }
    if (payload.nbf > now2 + tolerance) {
      throw new JWTClaimValidationFailed('"nbf" claim timestamp check failed', "nbf", "check_failed");
    }
  }
  if (payload.exp !== void 0) {
    if (typeof payload.exp !== "number") {
      throw new JWTClaimValidationFailed('"exp" claim must be a number', "exp", "invalid");
    }
    if (payload.exp <= now2 - tolerance) {
      throw new JWTExpired('"exp" claim timestamp check failed', "exp", "check_failed");
    }
  }
  if (maxTokenAge) {
    const age = now2 - payload.iat;
    const max = typeof maxTokenAge === "number" ? maxTokenAge : secs(maxTokenAge);
    if (age - tolerance > max) {
      throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', "iat", "check_failed");
    }
    if (age < 0 - tolerance) {
      throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', "iat", "check_failed");
    }
  }
  return payload;
};
async function jwtDecrypt(jwt2, key, options) {
  const decrypted = await compactDecrypt(jwt2, key, options);
  const payload = jwtPayload(decrypted.protectedHeader, decrypted.plaintext, options);
  const { protectedHeader } = decrypted;
  if (protectedHeader.iss !== void 0 && protectedHeader.iss !== payload.iss) {
    throw new JWTClaimValidationFailed('replicated "iss" claim header parameter mismatch', "iss", "mismatch");
  }
  if (protectedHeader.sub !== void 0 && protectedHeader.sub !== payload.sub) {
    throw new JWTClaimValidationFailed('replicated "sub" claim header parameter mismatch', "sub", "mismatch");
  }
  if (protectedHeader.aud !== void 0 && JSON.stringify(protectedHeader.aud) !== JSON.stringify(payload.aud)) {
    throw new JWTClaimValidationFailed('replicated "aud" claim header parameter mismatch', "aud", "mismatch");
  }
  const result = { payload, protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: decrypted.key };
  }
  return result;
}
class CompactEncrypt {
  _flattened;
  constructor(plaintext) {
    this._flattened = new FlattenedEncrypt(plaintext);
  }
  setContentEncryptionKey(cek) {
    this._flattened.setContentEncryptionKey(cek);
    return this;
  }
  setInitializationVector(iv) {
    this._flattened.setInitializationVector(iv);
    return this;
  }
  setProtectedHeader(protectedHeader) {
    this._flattened.setProtectedHeader(protectedHeader);
    return this;
  }
  setKeyManagementParameters(parameters) {
    this._flattened.setKeyManagementParameters(parameters);
    return this;
  }
  async encrypt(key, options) {
    const jwe = await this._flattened.encrypt(key, options);
    return [jwe.protected, jwe.encrypted_key, jwe.iv, jwe.ciphertext, jwe.tag].join(".");
  }
}
function validateInput(label, input) {
  if (!Number.isFinite(input)) {
    throw new TypeError(`Invalid ${label} input`);
  }
  return input;
}
class ProduceJWT {
  _payload;
  constructor(payload = {}) {
    if (!isObject$1(payload)) {
      throw new TypeError("JWT Claims Set MUST be an object");
    }
    this._payload = payload;
  }
  setIssuer(issuer) {
    this._payload = { ...this._payload, iss: issuer };
    return this;
  }
  setSubject(subject) {
    this._payload = { ...this._payload, sub: subject };
    return this;
  }
  setAudience(audience) {
    this._payload = { ...this._payload, aud: audience };
    return this;
  }
  setJti(jwtId) {
    this._payload = { ...this._payload, jti: jwtId };
    return this;
  }
  setNotBefore(input) {
    if (typeof input === "number") {
      this._payload = { ...this._payload, nbf: validateInput("setNotBefore", input) };
    } else if (input instanceof Date) {
      this._payload = { ...this._payload, nbf: validateInput("setNotBefore", epoch(input)) };
    } else {
      this._payload = { ...this._payload, nbf: epoch(/* @__PURE__ */ new Date()) + secs(input) };
    }
    return this;
  }
  setExpirationTime(input) {
    if (typeof input === "number") {
      this._payload = { ...this._payload, exp: validateInput("setExpirationTime", input) };
    } else if (input instanceof Date) {
      this._payload = { ...this._payload, exp: validateInput("setExpirationTime", epoch(input)) };
    } else {
      this._payload = { ...this._payload, exp: epoch(/* @__PURE__ */ new Date()) + secs(input) };
    }
    return this;
  }
  setIssuedAt(input) {
    if (typeof input === "undefined") {
      this._payload = { ...this._payload, iat: epoch(/* @__PURE__ */ new Date()) };
    } else if (input instanceof Date) {
      this._payload = { ...this._payload, iat: validateInput("setIssuedAt", epoch(input)) };
    } else if (typeof input === "string") {
      this._payload = {
        ...this._payload,
        iat: validateInput("setIssuedAt", epoch(/* @__PURE__ */ new Date()) + secs(input))
      };
    } else {
      this._payload = { ...this._payload, iat: validateInput("setIssuedAt", input) };
    }
    return this;
  }
}
class EncryptJWT extends ProduceJWT {
  _cek;
  _iv;
  _keyManagementParameters;
  _protectedHeader;
  _replicateIssuerAsHeader;
  _replicateSubjectAsHeader;
  _replicateAudienceAsHeader;
  setProtectedHeader(protectedHeader) {
    if (this._protectedHeader) {
      throw new TypeError("setProtectedHeader can only be called once");
    }
    this._protectedHeader = protectedHeader;
    return this;
  }
  setKeyManagementParameters(parameters) {
    if (this._keyManagementParameters) {
      throw new TypeError("setKeyManagementParameters can only be called once");
    }
    this._keyManagementParameters = parameters;
    return this;
  }
  setContentEncryptionKey(cek) {
    if (this._cek) {
      throw new TypeError("setContentEncryptionKey can only be called once");
    }
    this._cek = cek;
    return this;
  }
  setInitializationVector(iv) {
    if (this._iv) {
      throw new TypeError("setInitializationVector can only be called once");
    }
    this._iv = iv;
    return this;
  }
  replicateIssuerAsHeader() {
    this._replicateIssuerAsHeader = true;
    return this;
  }
  replicateSubjectAsHeader() {
    this._replicateSubjectAsHeader = true;
    return this;
  }
  replicateAudienceAsHeader() {
    this._replicateAudienceAsHeader = true;
    return this;
  }
  async encrypt(key, options) {
    const enc2 = new CompactEncrypt(encoder$1.encode(JSON.stringify(this._payload)));
    if (this._replicateIssuerAsHeader) {
      this._protectedHeader = { ...this._protectedHeader, iss: this._payload.iss };
    }
    if (this._replicateSubjectAsHeader) {
      this._protectedHeader = { ...this._protectedHeader, sub: this._payload.sub };
    }
    if (this._replicateAudienceAsHeader) {
      this._protectedHeader = { ...this._protectedHeader, aud: this._payload.aud };
    }
    enc2.setProtectedHeader(this._protectedHeader);
    if (this._iv) {
      enc2.setInitializationVector(this._iv);
    }
    if (this._cek) {
      enc2.setContentEncryptionKey(this._cek);
    }
    if (this._keyManagementParameters) {
      enc2.setKeyManagementParameters(this._keyManagementParameters);
    }
    return enc2.encrypt(key, options);
  }
}
const check = (value, description) => {
  if (typeof value !== "string" || !value) {
    throw new JWKInvalid(`${description} missing or invalid`);
  }
};
async function calculateJwkThumbprint(jwk, digestAlgorithm) {
  if (!isObject$1(jwk)) {
    throw new TypeError("JWK must be an object");
  }
  digestAlgorithm ??= "sha256";
  if (digestAlgorithm !== "sha256" && digestAlgorithm !== "sha384" && digestAlgorithm !== "sha512") {
    throw new TypeError('digestAlgorithm must one of "sha256", "sha384", or "sha512"');
  }
  let components;
  switch (jwk.kty) {
    case "EC":
      check(jwk.crv, '"crv" (Curve) Parameter');
      check(jwk.x, '"x" (X Coordinate) Parameter');
      check(jwk.y, '"y" (Y Coordinate) Parameter');
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
      break;
    case "OKP":
      check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter');
      check(jwk.x, '"x" (Public Key) Parameter');
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
      break;
    case "RSA":
      check(jwk.e, '"e" (Exponent) Parameter');
      check(jwk.n, '"n" (Modulus) Parameter');
      components = { e: jwk.e, kty: jwk.kty, n: jwk.n };
      break;
    case "oct":
      check(jwk.k, '"k" (Key Value) Parameter');
      components = { k: jwk.k, kty: jwk.kty };
      break;
    default:
      throw new JOSENotSupported('"kty" (Key Type) Parameter missing or unsupported');
  }
  const data = encoder$1.encode(JSON.stringify(components));
  return encode$2(await digest(digestAlgorithm, data));
}
const encode$1 = encode$2;
const decode$1 = decode$2;
const DEFAULT_MAX_AGE = 30 * 24 * 60 * 60;
const now = () => Date.now() / 1e3 | 0;
const alg = "dir";
const enc = "A256CBC-HS512";
async function encode(params) {
  const { token = {}, secret, maxAge = DEFAULT_MAX_AGE, salt } = params;
  const secrets = Array.isArray(secret) ? secret : [secret];
  const encryptionSecret = await getDerivedEncryptionKey(enc, secrets[0], salt);
  const thumbprint = await calculateJwkThumbprint({ kty: "oct", k: encode$1(encryptionSecret) }, `sha${encryptionSecret.byteLength << 3}`);
  return await new EncryptJWT(token).setProtectedHeader({ alg, enc, kid: thumbprint }).setIssuedAt().setExpirationTime(now() + maxAge).setJti(crypto.randomUUID()).encrypt(encryptionSecret);
}
async function decode(params) {
  const { token, secret, salt } = params;
  const secrets = Array.isArray(secret) ? secret : [secret];
  if (!token)
    return null;
  const { payload } = await jwtDecrypt(token, async ({ kid, enc: enc2 }) => {
    for (const secret2 of secrets) {
      const encryptionSecret = await getDerivedEncryptionKey(enc2, secret2, salt);
      if (kid === void 0)
        return encryptionSecret;
      const thumbprint = await calculateJwkThumbprint({ kty: "oct", k: encode$1(encryptionSecret) }, `sha${encryptionSecret.byteLength << 3}`);
      if (kid === thumbprint)
        return encryptionSecret;
    }
    throw new Error("no matching decryption secret");
  }, {
    clockTolerance: 15,
    keyManagementAlgorithms: [alg],
    contentEncryptionAlgorithms: [enc, "A256GCM"]
  });
  return payload;
}
async function getDerivedEncryptionKey(enc2, keyMaterial, salt) {
  let length;
  switch (enc2) {
    case "A256CBC-HS512":
      length = 64;
      break;
    case "A256GCM":
      length = 32;
      break;
    default:
      throw new Error("Unsupported JWT Content Encryption Algorithm");
  }
  return await hkdf("sha256", keyMaterial, salt, `Auth.js Generated Encryption Key (${salt})`, length);
}
async function createCallbackUrl({ options, paramValue, cookieValue }) {
  const { url, callbacks } = options;
  let callbackUrl = url.origin;
  if (paramValue) {
    callbackUrl = await callbacks.redirect({
      url: paramValue,
      baseUrl: url.origin
    });
  } else if (cookieValue) {
    callbackUrl = await callbacks.redirect({
      url: cookieValue,
      baseUrl: url.origin
    });
  }
  return {
    callbackUrl,
    // Save callback URL in a cookie so that it can be used for subsequent requests in signin/signout/callback flow
    callbackUrlCookie: callbackUrl !== cookieValue ? callbackUrl : void 0
  };
}
const red = "\x1B[31m";
const yellow = "\x1B[33m";
const grey = "\x1B[90m";
const reset = "\x1B[0m";
const logger = {
  error(error) {
    const name = error instanceof AuthError ? error.type : error.name;
    console.error(`${red}[auth][error]${reset} ${name}: ${error.message}`);
    if (error.cause && typeof error.cause === "object" && "err" in error.cause && error.cause.err instanceof Error) {
      const { err, ...data } = error.cause;
      console.error(`${red}[auth][cause]${reset}:`, err.stack);
      if (data)
        console.error(`${red}[auth][details]${reset}:`, JSON.stringify(data, null, 2));
    } else if (error.stack) {
      console.error(error.stack.replace(/.*/, "").substring(1));
    }
  },
  warn(code) {
    const url = `https://warnings.authjs.dev#${code}`;
    console.warn(`${yellow}[auth][warn][${code}]${reset}`, `Read more: ${url}`);
  },
  debug(message2, metadata) {
    console.log(`${grey}[auth][debug]:${reset} ${message2}`, JSON.stringify(metadata, null, 2));
  }
};
function setLogger(newLogger = {}, debug) {
  if (!debug)
    logger.debug = () => {
    };
  if (newLogger.error)
    logger.error = newLogger.error;
  if (newLogger.warn)
    logger.warn = newLogger.warn;
  if (newLogger.debug)
    logger.debug = newLogger.debug;
}
const actions = [
  "providers",
  "session",
  "csrf",
  "signin",
  "signout",
  "callback",
  "verify-request",
  "error",
  "webauthn-options"
];
function isAuthAction(action) {
  return actions.includes(action);
}
async function getBody(req) {
  if (!("body" in req) || !req.body || req.method !== "POST")
    return;
  const contentType = req.headers.get("content-type");
  if (contentType?.includes("application/json")) {
    return await req.json();
  } else if (contentType?.includes("application/x-www-form-urlencoded")) {
    const params = new URLSearchParams(await req.text());
    return Object.fromEntries(params);
  }
}
async function toInternalRequest(req, config) {
  try {
    if (req.method !== "GET" && req.method !== "POST")
      throw new UnknownAction("Only GET and POST requests are supported.");
    config.basePath ?? (config.basePath = "/auth");
    const url = new URL(req.url);
    const { action, providerId } = parseActionAndProviderId(url.pathname, config.basePath);
    return {
      url,
      action,
      providerId,
      method: req.method,
      headers: Object.fromEntries(req.headers),
      body: req.body ? await getBody(req) : void 0,
      cookies: parse_1(req.headers.get("cookie") ?? "") ?? {},
      error: url.searchParams.get("error") ?? void 0,
      query: Object.fromEntries(url.searchParams)
    };
  } catch (e) {
    logger.error(e);
    logger.debug("request", req);
  }
}
function toRequest(request) {
  return new Request(request.url, {
    headers: request.headers,
    method: request.method,
    body: request.method === "POST" ? JSON.stringify(request.body ?? {}) : void 0
  });
}
function toResponse(res) {
  const headers = new Headers(res.headers);
  res.cookies?.forEach((cookie) => {
    const { name, value, options } = cookie;
    const cookieHeader = serialize_1(name, value, options);
    if (headers.has("Set-Cookie"))
      headers.append("Set-Cookie", cookieHeader);
    else
      headers.set("Set-Cookie", cookieHeader);
  });
  let body = res.body;
  if (headers.get("content-type") === "application/json")
    body = JSON.stringify(res.body);
  else if (headers.get("content-type") === "application/x-www-form-urlencoded")
    body = new URLSearchParams(res.body).toString();
  const status = res.redirect ? 302 : res.status ?? 200;
  const response = new Response(body, { headers, status });
  if (res.redirect)
    response.headers.set("Location", res.redirect);
  return response;
}
async function createHash(message2) {
  const data = new TextEncoder().encode(message2);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map((b2) => b2.toString(16).padStart(2, "0")).join("").toString();
}
function randomString(size) {
  const i2hex = (i2) => ("0" + i2.toString(16)).slice(-2);
  const r2 = (a2, i2) => a2 + i2hex(i2);
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  return Array.from(bytes).reduce(r2, "");
}
function parseActionAndProviderId(pathname, base2) {
  const a2 = pathname.match(new RegExp(`^${base2}(.+)`));
  if (a2 === null)
    throw new UnknownAction(`Cannot parse action at ${pathname}`);
  const [_2, actionAndProviderId] = a2;
  const b2 = actionAndProviderId.replace(/^\//, "").split("/");
  if (b2.length !== 1 && b2.length !== 2)
    throw new UnknownAction(`Cannot parse action at ${pathname}`);
  const [action, providerId] = b2;
  if (!isAuthAction(action))
    throw new UnknownAction(`Cannot parse action at ${pathname}`);
  if (providerId && !["signin", "callback", "webauthn-options"].includes(action))
    throw new UnknownAction(`Cannot parse action at ${pathname}`);
  return { action, providerId };
}
async function createCSRFToken({ options, cookieValue, isPost, bodyValue }) {
  if (cookieValue) {
    const [csrfToken2, csrfTokenHash2] = cookieValue.split("|");
    const expectedCsrfTokenHash = await createHash(`${csrfToken2}${options.secret}`);
    if (csrfTokenHash2 === expectedCsrfTokenHash) {
      const csrfTokenVerified = isPost && csrfToken2 === bodyValue;
      return { csrfTokenVerified, csrfToken: csrfToken2 };
    }
  }
  const csrfToken = randomString(32);
  const csrfTokenHash = await createHash(`${csrfToken}${options.secret}`);
  const cookie = `${csrfToken}|${csrfTokenHash}`;
  return { cookie, csrfToken };
}
function validateCSRF(action, verified) {
  if (verified)
    return;
  throw new MissingCSRF(`CSRF token was missing during an action ${action}.`);
}
function isObject(item) {
  return item && typeof item === "object" && !Array.isArray(item);
}
function merge(target, ...sources) {
  if (!sources.length)
    return target;
  const source = sources.shift();
  if (isObject(target) && isObject(source)) {
    for (const key in source) {
      if (isObject(source[key])) {
        if (!target[key])
          Object.assign(target, { [key]: {} });
        merge(target[key], source[key]);
      } else {
        Object.assign(target, { [key]: source[key] });
      }
    }
  }
  return merge(target, ...sources);
}
function parseProviders(params) {
  const { providerId, options } = params;
  const url = new URL(options.basePath ?? "/auth", params.url.origin);
  const providers = params.providers.map((p2) => {
    const provider = typeof p2 === "function" ? p2() : p2;
    const { options: userOptions, ...defaults } = provider;
    const id = userOptions?.id ?? defaults.id;
    const merged = merge(defaults, userOptions, {
      signinUrl: `${url}/signin/${id}`,
      callbackUrl: `${url}/callback/${id}`
    });
    if (provider.type === "oauth" || provider.type === "oidc") {
      merged.redirectProxyUrl ?? (merged.redirectProxyUrl = options.redirectProxyUrl);
      return normalizeOAuth(merged);
    }
    return merged;
  });
  return {
    providers,
    provider: providers.find(({ id }) => id === providerId)
  };
}
function normalizeOAuth(c2) {
  if (c2.issuer)
    c2.wellKnown ?? (c2.wellKnown = `${c2.issuer}/.well-known/openid-configuration`);
  const authorization = normalizeEndpoint(c2.authorization, c2.issuer);
  if (authorization && !authorization.url?.searchParams.has("scope")) {
    authorization.url.searchParams.set("scope", "openid profile email");
  }
  const token = normalizeEndpoint(c2.token, c2.issuer);
  const userinfo = normalizeEndpoint(c2.userinfo, c2.issuer);
  const checks = c2.checks ?? ["pkce"];
  if (c2.redirectProxyUrl) {
    if (!checks.includes("state"))
      checks.push("state");
    c2.redirectProxyUrl = `${c2.redirectProxyUrl}/callback/${c2.id}`;
  }
  return {
    ...c2,
    authorization,
    token,
    checks,
    userinfo,
    profile: c2.profile ?? defaultProfile,
    account: c2.account ?? defaultAccount
  };
}
const defaultProfile = (profile) => {
  return stripUndefined({
    id: profile.sub ?? profile.id ?? crypto.randomUUID(),
    name: profile.name ?? profile.nickname ?? profile.preferred_username,
    email: profile.email,
    image: profile.picture
  });
};
const defaultAccount = (account) => {
  return stripUndefined({
    access_token: account.access_token,
    id_token: account.id_token,
    refresh_token: account.refresh_token,
    expires_at: account.expires_at,
    scope: account.scope,
    token_type: account.token_type,
    session_state: account.session_state
  });
};
function stripUndefined(o2) {
  const result = {};
  for (let [k2, v2] of Object.entries(o2))
    v2 !== void 0 && (result[k2] = v2);
  return result;
}
function normalizeEndpoint(e, issuer) {
  if (!e && issuer)
    return;
  if (typeof e === "string") {
    return { url: new URL(e) };
  }
  const url = new URL(e?.url ?? "https://authjs.dev");
  if (e?.params != null) {
    for (let [key, value] of Object.entries(e.params)) {
      if (key === "claims")
        value = JSON.stringify(value);
      url.searchParams.set(key, String(value));
    }
  }
  return { url, request: e?.request, conform: e?.conform };
}
const defaultCallbacks = {
  signIn() {
    return true;
  },
  redirect({ url, baseUrl }) {
    if (url.startsWith("/"))
      return `${baseUrl}${url}`;
    else if (new URL(url).origin === baseUrl)
      return url;
    return baseUrl;
  },
  session({ session: session2 }) {
    return {
      user: {
        name: session2.user?.name,
        email: session2.user?.email,
        image: session2.user?.image
      },
      expires: session2.expires?.toISOString?.() ?? session2.expires
    };
  },
  jwt({ token }) {
    return token;
  }
};
async function init({ authOptions, providerId, action, url, cookies: reqCookies, callbackUrl: reqCallbackUrl, csrfToken: reqCsrfToken, csrfDisabled, isPost }) {
  const { providers, provider } = parseProviders({
    providers: authOptions.providers,
    url,
    providerId,
    options: authOptions
  });
  const maxAge = 30 * 24 * 60 * 60;
  let isOnRedirectProxy = false;
  if ((provider?.type === "oauth" || provider?.type === "oidc") && provider.redirectProxyUrl) {
    try {
      isOnRedirectProxy = new URL(provider.redirectProxyUrl).origin === url.origin;
    } catch {
      throw new TypeError(`redirectProxyUrl must be a valid URL. Received: ${provider.redirectProxyUrl}`);
    }
  }
  const options = {
    debug: false,
    pages: {},
    theme: {
      colorScheme: "auto",
      logo: "",
      brandColor: "",
      buttonText: ""
    },
    // Custom options override defaults
    ...authOptions,
    // These computed settings can have values in userOptions but we override them
    // and are request-specific.
    url,
    action,
    // @ts-expect-errors
    provider,
    cookies: merge(defaultCookies(authOptions.useSecureCookies ?? url.protocol === "https:"), authOptions.cookies),
    providers,
    // Session options
    session: {
      // If no adapter specified, force use of JSON Web Tokens (stateless)
      strategy: authOptions.adapter ? "database" : "jwt",
      maxAge,
      updateAge: 24 * 60 * 60,
      generateSessionToken: () => crypto.randomUUID(),
      ...authOptions.session
    },
    // JWT options
    jwt: {
      secret: authOptions.secret,
      // Asserted in assert.ts
      maxAge: authOptions.session?.maxAge ?? maxAge,
      // default to same as `session.maxAge`
      encode,
      decode,
      ...authOptions.jwt
    },
    // Event messages
    events: eventsErrorHandler(authOptions.events ?? {}, logger),
    adapter: adapterErrorHandler(authOptions.adapter, logger),
    // Callback functions
    callbacks: { ...defaultCallbacks, ...authOptions.callbacks },
    logger,
    callbackUrl: url.origin,
    isOnRedirectProxy,
    experimental: {
      ...authOptions.experimental
    }
  };
  const cookies = [];
  if (csrfDisabled) {
    options.csrfTokenVerified = true;
  } else {
    const { csrfToken, cookie: csrfCookie, csrfTokenVerified } = await createCSRFToken({
      options,
      cookieValue: reqCookies?.[options.cookies.csrfToken.name],
      isPost,
      bodyValue: reqCsrfToken
    });
    options.csrfToken = csrfToken;
    options.csrfTokenVerified = csrfTokenVerified;
    if (csrfCookie) {
      cookies.push({
        name: options.cookies.csrfToken.name,
        value: csrfCookie,
        options: options.cookies.csrfToken.options
      });
    }
  }
  const { callbackUrl, callbackUrlCookie } = await createCallbackUrl({
    options,
    cookieValue: reqCookies?.[options.cookies.callbackUrl.name],
    paramValue: reqCallbackUrl
  });
  options.callbackUrl = callbackUrl;
  if (callbackUrlCookie) {
    cookies.push({
      name: options.cookies.callbackUrl.name,
      value: callbackUrlCookie,
      options: options.cookies.callbackUrl.options
    });
  }
  return { options, cookies };
}
function eventsErrorHandler(methods, logger2) {
  return Object.keys(methods).reduce((acc, name) => {
    acc[name] = async (...args) => {
      try {
        const method = methods[name];
        return await method(...args);
      } catch (e) {
        logger2.error(new EventError(e));
      }
    };
    return acc;
  }, {});
}
function adapterErrorHandler(adapter, logger2) {
  if (!adapter)
    return;
  return Object.keys(adapter).reduce((acc, name) => {
    acc[name] = async (...args) => {
      try {
        logger2.debug(`adapter_${name}`, { args });
        const method = adapter[name];
        return await method(...args);
      } catch (e) {
        const error = new AdapterError(e);
        logger2.error(error);
        throw error;
      }
    };
    return acc;
  }, {});
}
var l$1;
function p$1(n2) {
  return n2.children;
}
l$1 = { __e: function(n2, l2, u2, i2) {
  for (var t, o2, r2; l2 = l2.__; )
    if ((t = l2.__c) && !t.__)
      try {
        if ((o2 = t.constructor) && null != o2.getDerivedStateFromError && (t.setState(o2.getDerivedStateFromError(n2)), r2 = t.__d), null != t.componentDidCatch && (t.componentDidCatch(n2, i2 || {}), r2 = t.__d), r2)
          return t.__E = t;
      } catch (l3) {
        n2 = l3;
      }
  throw n2;
} };
var r = /acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|^--/i, n = /^(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)$/, o$1 = /[\s\n\\/='"\0<>]/, i = /^xlink:?./, a = /["&<]/;
function l(e) {
  if (false === a.test(e += ""))
    return e;
  for (var t = 0, r2 = 0, n2 = "", o2 = ""; r2 < e.length; r2++) {
    switch (e.charCodeAt(r2)) {
      case 34:
        o2 = "&quot;";
        break;
      case 38:
        o2 = "&amp;";
        break;
      case 60:
        o2 = "&lt;";
        break;
      default:
        continue;
    }
    r2 !== t && (n2 += e.slice(t, r2)), n2 += o2, t = r2 + 1;
  }
  return r2 !== t && (n2 += e.slice(t, r2)), n2;
}
var s = function(e, t) {
  return String(e).replace(/(\n+)/g, "$1" + (t || "	"));
}, f = function(e, t, r2) {
  return String(e).length > (t || 40) || !r2 && -1 !== String(e).indexOf("\n") || -1 !== String(e).indexOf("<");
}, c = {}, u = /([A-Z])/g;
function p(e) {
  var t = "";
  for (var n2 in e) {
    var o2 = e[n2];
    null != o2 && "" !== o2 && (t && (t += " "), t += "-" == n2[0] ? n2 : c[n2] || (c[n2] = n2.replace(u, "-$1").toLowerCase()), t = "number" == typeof o2 && false === r.test(n2) ? t + ": " + o2 + "px;" : t + ": " + o2 + ";");
  }
  return t || void 0;
}
function _$1(e, t) {
  return Array.isArray(t) ? t.reduce(_$1, e) : null != t && false !== t && e.push(t), e;
}
function d() {
  this.__d = true;
}
function v(e, t) {
  return { __v: e, context: t, props: e.props, setState: d, forceUpdate: d, __d: true, __h: [] };
}
function h(e, t) {
  var r2 = e.contextType, n2 = r2 && t[r2.__c];
  return null != r2 ? n2 ? n2.props.value : r2.__ : t;
}
var g = [];
function y(r2, a2, c2, u2, d2, m2) {
  if (null == r2 || "boolean" == typeof r2)
    return "";
  if ("object" != typeof r2)
    return l(r2);
  var b2 = c2.pretty, x2 = b2 && "string" == typeof b2 ? b2 : "	";
  if (Array.isArray(r2)) {
    for (var k2 = "", S2 = 0; S2 < r2.length; S2++)
      b2 && S2 > 0 && (k2 += "\n"), k2 += y(r2[S2], a2, c2, u2, d2, m2);
    return k2;
  }
  var w2, C2 = r2.type, O2 = r2.props, j2 = false;
  if ("function" == typeof C2) {
    if (j2 = true, !c2.shallow || !u2 && false !== c2.renderRootComponent) {
      if (C2 === p$1) {
        var A = [];
        return _$1(A, r2.props.children), y(A, a2, c2, false !== c2.shallowHighOrder, d2, m2);
      }
      var F, H = r2.__c = v(r2, a2);
      l$1.__b && l$1.__b(r2);
      var M = l$1.__r;
      if (C2.prototype && "function" == typeof C2.prototype.render) {
        var L = h(C2, a2);
        (H = r2.__c = new C2(O2, L)).__v = r2, H._dirty = H.__d = true, H.props = O2, null == H.state && (H.state = {}), null == H._nextState && null == H.__s && (H._nextState = H.__s = H.state), H.context = L, C2.getDerivedStateFromProps ? H.state = Object.assign({}, H.state, C2.getDerivedStateFromProps(H.props, H.state)) : H.componentWillMount && (H.componentWillMount(), H.state = H._nextState !== H.state ? H._nextState : H.__s !== H.state ? H.__s : H.state), M && M(r2), F = H.render(H.props, H.state, H.context);
      } else
        for (var T = h(C2, a2), E = 0; H.__d && E++ < 25; )
          H.__d = false, M && M(r2), F = C2.call(r2.__c, O2, T);
      return H.getChildContext && (a2 = Object.assign({}, a2, H.getChildContext())), l$1.diffed && l$1.diffed(r2), y(F, a2, c2, false !== c2.shallowHighOrder, d2, m2);
    }
    C2 = (w2 = C2).displayName || w2 !== Function && w2.name || function(e) {
      var t = (Function.prototype.toString.call(e).match(/^\s*function\s+([^( ]+)/) || "")[1];
      if (!t) {
        for (var r3 = -1, n2 = g.length; n2--; )
          if (g[n2] === e) {
            r3 = n2;
            break;
          }
        r3 < 0 && (r3 = g.push(e) - 1), t = "UnnamedComponent" + r3;
      }
      return t;
    }(w2);
  }
  var $, D, N = "<" + C2;
  if (O2) {
    var P = Object.keys(O2);
    c2 && true === c2.sortAttributes && P.sort();
    for (var W = 0; W < P.length; W++) {
      var I = P[W], R = O2[I];
      if ("children" !== I) {
        if (!o$1.test(I) && (c2 && c2.allAttributes || "key" !== I && "ref" !== I && "__self" !== I && "__source" !== I)) {
          if ("defaultValue" === I)
            I = "value";
          else if ("defaultChecked" === I)
            I = "checked";
          else if ("defaultSelected" === I)
            I = "selected";
          else if ("className" === I) {
            if (void 0 !== O2.class)
              continue;
            I = "class";
          } else
            d2 && i.test(I) && (I = I.toLowerCase().replace(/^xlink:?/, "xlink:"));
          if ("htmlFor" === I) {
            if (O2.for)
              continue;
            I = "for";
          }
          "style" === I && R && "object" == typeof R && (R = p(R)), "a" === I[0] && "r" === I[1] && "boolean" == typeof R && (R = String(R));
          var U = c2.attributeHook && c2.attributeHook(I, R, a2, c2, j2);
          if (U || "" === U)
            N += U;
          else if ("dangerouslySetInnerHTML" === I)
            D = R && R.__html;
          else if ("textarea" === C2 && "value" === I)
            $ = R;
          else if ((R || 0 === R || "" === R) && "function" != typeof R) {
            if (!(true !== R && "" !== R || (R = I, c2 && c2.xml))) {
              N = N + " " + I;
              continue;
            }
            if ("value" === I) {
              if ("select" === C2) {
                m2 = R;
                continue;
              }
              "option" === C2 && m2 == R && void 0 === O2.selected && (N += " selected");
            }
            N = N + " " + I + '="' + l(R) + '"';
          }
        }
      } else
        $ = R;
    }
  }
  if (b2) {
    var V = N.replace(/\n\s*/, " ");
    V === N || ~V.indexOf("\n") ? b2 && ~N.indexOf("\n") && (N += "\n") : N = V;
  }
  if (N += ">", o$1.test(C2))
    throw new Error(C2 + " is not a valid HTML tag name in " + N);
  var q, z = n.test(C2) || c2.voidElements && c2.voidElements.test(C2), Z = [];
  if (D)
    b2 && f(D) && (D = "\n" + x2 + s(D, x2)), N += D;
  else if (null != $ && _$1(q = [], $).length) {
    for (var B = b2 && ~N.indexOf("\n"), G = false, J = 0; J < q.length; J++) {
      var K = q[J];
      if (null != K && false !== K) {
        var Q = y(K, a2, c2, true, "svg" === C2 || "foreignObject" !== C2 && d2, m2);
        if (b2 && !B && f(Q) && (B = true), Q)
          if (b2) {
            var X = Q.length > 0 && "<" != Q[0];
            G && X ? Z[Z.length - 1] += Q : Z.push(Q), G = X;
          } else
            Z.push(Q);
      }
    }
    if (b2 && B)
      for (var Y = Z.length; Y--; )
        Z[Y] = "\n" + x2 + s(Z[Y], x2);
  }
  if (Z.length || D)
    N += Z.join("");
  else if (c2 && c2.xml)
    return N.substring(0, N.length - 1) + " />";
  return !z || q || D ? (b2 && ~N.indexOf("\n") && (N += "\n"), N = N + "</" + C2 + ">") : N = N.replace(/>$/, " />"), N;
}
var m = { shallow: true };
k.render = k;
var b = function(e, t) {
  return k(e, t, m);
}, x = [];
function k(e, r2, n2) {
  r2 = r2 || {};
  var o2, i2 = l$1.__s;
  return l$1.__s = true, o2 = n2 && (n2.pretty || n2.voidElements || n2.sortAttributes || n2.shallow || n2.allAttributes || n2.xml || n2.attributeHook) ? y(e, r2, n2) : j(e, r2, false, void 0), l$1.__c && l$1.__c(e, x), l$1.__s = i2, x.length = 0, o2;
}
function S(e, t) {
  return "className" === e ? "class" : "htmlFor" === e ? "for" : "defaultValue" === e ? "value" : "defaultChecked" === e ? "checked" : "defaultSelected" === e ? "selected" : t && i.test(e) ? e.toLowerCase().replace(/^xlink:?/, "xlink:") : e;
}
function w(e, t) {
  return "style" === e && null != t && "object" == typeof t ? p(t) : "a" === e[0] && "r" === e[1] && "boolean" == typeof t ? String(t) : t;
}
var C = Array.isArray, O = Object.assign;
function j(r2, i2, a2, s2) {
  if (null == r2 || true === r2 || false === r2 || "" === r2)
    return "";
  if ("object" != typeof r2)
    return l(r2);
  if (C(r2)) {
    for (var f2 = "", c2 = 0; c2 < r2.length; c2++)
      f2 += j(r2[c2], i2, a2, s2);
    return f2;
  }
  l$1.__b && l$1.__b(r2);
  var u2 = r2.type, p2 = r2.props;
  if ("function" == typeof u2) {
    if (u2 === p$1)
      return j(r2.props.children, i2, a2, s2);
    var _2;
    _2 = u2.prototype && "function" == typeof u2.prototype.render ? function(e, r3) {
      var n2 = e.type, o2 = h(n2, r3), i3 = new n2(e.props, o2);
      e.__c = i3, i3.__v = e, i3.__d = true, i3.props = e.props, null == i3.state && (i3.state = {}), null == i3.__s && (i3.__s = i3.state), i3.context = o2, n2.getDerivedStateFromProps ? i3.state = O({}, i3.state, n2.getDerivedStateFromProps(i3.props, i3.state)) : i3.componentWillMount && (i3.componentWillMount(), i3.state = i3.__s !== i3.state ? i3.__s : i3.state);
      var a3 = l$1.__r;
      return a3 && a3(e), i3.render(i3.props, i3.state, i3.context);
    }(r2, i2) : function(e, r3) {
      var n2, o2 = v(e, r3), i3 = h(e.type, r3);
      e.__c = o2;
      for (var a3 = l$1.__r, l2 = 0; o2.__d && l2++ < 25; )
        o2.__d = false, a3 && a3(e), n2 = e.type.call(o2, e.props, i3);
      return n2;
    }(r2, i2);
    var d2 = r2.__c;
    d2.getChildContext && (i2 = O({}, i2, d2.getChildContext()));
    var g2 = j(_2, i2, a2, s2);
    return l$1.diffed && l$1.diffed(r2), g2;
  }
  var y2, m2, b2 = "<";
  if (b2 += u2, p2)
    for (var x2 in y2 = p2.children, p2) {
      var k2 = p2[x2];
      if (!("key" === x2 || "ref" === x2 || "__self" === x2 || "__source" === x2 || "children" === x2 || "className" === x2 && "class" in p2 || "htmlFor" === x2 && "for" in p2 || o$1.test(x2))) {
        if (k2 = w(x2 = S(x2, a2), k2), "dangerouslySetInnerHTML" === x2)
          m2 = k2 && k2.__html;
        else if ("textarea" === u2 && "value" === x2)
          y2 = k2;
        else if ((k2 || 0 === k2 || "" === k2) && "function" != typeof k2) {
          if (true === k2 || "" === k2) {
            k2 = x2, b2 = b2 + " " + x2;
            continue;
          }
          if ("value" === x2) {
            if ("select" === u2) {
              s2 = k2;
              continue;
            }
            "option" !== u2 || s2 != k2 || "selected" in p2 || (b2 += " selected");
          }
          b2 = b2 + " " + x2 + '="' + l(k2) + '"';
        }
      }
    }
  var A = b2;
  if (b2 += ">", o$1.test(u2))
    throw new Error(u2 + " is not a valid HTML tag name in " + b2);
  var F = "", H = false;
  if (m2)
    F += m2, H = true;
  else if ("string" == typeof y2)
    F += l(y2), H = true;
  else if (C(y2))
    for (var M = 0; M < y2.length; M++) {
      var L = y2[M];
      if (null != L && false !== L) {
        var T = j(L, i2, "svg" === u2 || "foreignObject" !== u2 && a2, s2);
        T && (F += T, H = true);
      }
    }
  else if (null != y2 && false !== y2 && true !== y2) {
    var E = j(y2, i2, "svg" === u2 || "foreignObject" !== u2 && a2, s2);
    E && (F += E, H = true);
  }
  if (l$1.diffed && l$1.diffed(r2), H)
    b2 += F;
  else if (n.test(u2))
    return A + " />";
  return b2 + "</" + u2 + ">";
}
k.shallowRender = b;
var _ = 0;
function o(o2, e, n2, t, f2) {
  var l2, s2, u2 = {};
  for (s2 in e)
    "ref" == s2 ? l2 = e[s2] : u2[s2] = e[s2];
  var a2 = { type: o2, props: u2, key: n2, ref: l2, __k: null, __: null, __b: 0, __e: null, __d: void 0, __c: null, __h: null, constructor: void 0, __v: --_, __source: f2, __self: t };
  if ("function" == typeof o2 && (l2 = o2.defaultProps))
    for (s2 in l2)
      void 0 === u2[s2] && (u2[s2] = l2[s2]);
  return l$1.vnode && l$1.vnode(a2), a2;
}
function ErrorPage(props) {
  const { url, error = "default", theme } = props;
  const signinPageUrl = `${url}/signin`;
  const errors = {
    default: {
      status: 200,
      heading: "Error",
      message: o("p", { children: o("a", { className: "site", href: url?.origin, children: url?.host }) })
    },
    Configuration: {
      status: 500,
      heading: "Server error",
      message: o("div", { children: [o("p", { children: "There is a problem with the server configuration." }), o("p", { children: "Check the server logs for more information." })] })
    },
    AccessDenied: {
      status: 403,
      heading: "Access Denied",
      message: o("div", { children: [o("p", { children: "You do not have permission to sign in." }), o("p", { children: o("a", { className: "button", href: signinPageUrl, children: "Sign in" }) })] })
    },
    Verification: {
      status: 403,
      heading: "Unable to sign in",
      message: o("div", { children: [o("p", { children: "The sign in link is no longer valid." }), o("p", { children: "It may have been used already or it may have expired." })] }),
      signin: o("a", { className: "button", href: signinPageUrl, children: "Sign in" })
    }
  };
  const { status, heading, message: message2, signin } = errors[error] ?? errors.default;
  return {
    status,
    html: o("div", { className: "error", children: [theme?.brandColor && o("style", { dangerouslySetInnerHTML: {
      __html: `
        :root {
          --brand-color: ${theme?.brandColor}
        }
      `
    } }), o("div", { className: "card", children: [theme?.logo && o("img", { src: theme?.logo, alt: "Logo", className: "logo" }), o("h1", { children: heading }), o("div", { className: "message", children: message2 }), signin] })] })
  };
}
async function webauthnScript(authURL, providerID) {
  const WebAuthnBrowser = window.SimpleWebAuthnBrowser;
  async function fetchOptions(action) {
    const url = new URL(`${authURL}/webauthn-options/${providerID}`);
    if (action)
      url.searchParams.append("action", action);
    const formFields = getFormFields();
    formFields.forEach((field) => {
      url.searchParams.append(field.name, field.value);
    });
    const res = await fetch(url);
    if (!res.ok) {
      console.error("Failed to fetch options", res);
      return;
    }
    return res.json();
  }
  function getForm() {
    const formID = `#${providerID}-form`;
    const form = document.querySelector(formID);
    if (!form)
      throw new Error(`Form '${formID}' not found`);
    return form;
  }
  function getFormFields() {
    const form = getForm();
    const formFields = Array.from(form.querySelectorAll("input[data-form-field]"));
    return formFields;
  }
  async function submitForm(action, data) {
    const form = getForm();
    if (action) {
      const actionInput = document.createElement("input");
      actionInput.type = "hidden";
      actionInput.name = "action";
      actionInput.value = action;
      form.appendChild(actionInput);
    }
    if (data) {
      const dataInput = document.createElement("input");
      dataInput.type = "hidden";
      dataInput.name = "data";
      dataInput.value = JSON.stringify(data);
      form.appendChild(dataInput);
    }
    return form.submit();
  }
  async function authenticationFlow(options, autofill) {
    const authResp = await WebAuthnBrowser.startAuthentication(options, autofill);
    return await submitForm("authenticate", authResp);
  }
  async function registrationFlow(options) {
    const formFields = getFormFields();
    formFields.forEach((field) => {
      if (field.required && !field.value) {
        throw new Error(`Missing required field: ${field.name}`);
      }
    });
    const regResp = await WebAuthnBrowser.startRegistration(options);
    return await submitForm("register", regResp);
  }
  async function autofillAuthentication() {
    if (!WebAuthnBrowser.browserSupportsWebAuthnAutofill())
      return;
    const res = await fetchOptions("authenticate");
    if (!res) {
      console.error("Failed to fetch option for autofill authentication");
      return;
    }
    try {
      await authenticationFlow(res.options, true);
    } catch (e) {
      console.error(e);
    }
  }
  async function setupForm() {
    const form = getForm();
    if (!WebAuthnBrowser.browserSupportsWebAuthn()) {
      form.style.display = "none";
      return;
    }
    if (form) {
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const res = await fetchOptions(void 0);
        if (!res) {
          console.error("Failed to fetch options for form submission");
          return;
        }
        if (res.action === "authenticate") {
          try {
            await authenticationFlow(res.options, false);
          } catch (e2) {
            console.error(e2);
          }
        } else if (res.action === "register") {
          try {
            await registrationFlow(res.options);
          } catch (e2) {
            console.error(e2);
          }
        }
      });
    }
  }
  setupForm();
  autofillAuthentication();
}
const signinErrors = {
  default: "Unable to sign in.",
  Signin: "Try signing in with a different account.",
  OAuthSignin: "Try signing in with a different account.",
  OAuthCallbackError: "Try signing in with a different account.",
  OAuthCreateAccount: "Try signing in with a different account.",
  EmailCreateAccount: "Try signing in with a different account.",
  Callback: "Try signing in with a different account.",
  OAuthAccountNotLinked: "To confirm your identity, sign in with the same account you used originally.",
  EmailSignin: "The e-mail could not be sent.",
  CredentialsSignin: "Sign in failed. Check the details you provided are correct.",
  SessionRequired: "Please sign in to access this page."
};
function hexToRgba(hex, alpha = 1) {
  if (!hex) {
    return;
  }
  hex = hex.replace(/^#/, "");
  if (hex.length === 3) {
    hex = hex[0] + hex[0] + hex[1] + hex[1] + hex[2] + hex[2];
  }
  const bigint = parseInt(hex, 16);
  const r2 = bigint >> 16 & 255;
  const g2 = bigint >> 8 & 255;
  const b2 = bigint & 255;
  alpha = Math.min(Math.max(alpha, 0), 1);
  const rgba = `rgba(${r2}, ${g2}, ${b2}, ${alpha})`;
  return rgba;
}
function ConditionalUIScript(providerID) {
  const startConditionalUIScript = `
const currentURL = window.location.href;
const authURL = currentURL.substring(0, currentURL.lastIndexOf('/'));
(${webauthnScript})(authURL, "${providerID}");
`;
  return o(p$1, { children: o("script", { dangerouslySetInnerHTML: { __html: startConditionalUIScript } }) });
}
function SigninPage(props) {
  const { csrfToken, providers = [], callbackUrl, theme, email, error: errorType } = props;
  if (typeof document !== "undefined" && theme?.brandColor) {
    document.documentElement.style.setProperty("--brand-color", theme.brandColor);
  }
  if (typeof document !== "undefined" && theme?.buttonText) {
    document.documentElement.style.setProperty("--button-text-color", theme.buttonText);
  }
  const error = errorType && (signinErrors[errorType] ?? signinErrors.default);
  const providerLogoPath = "https://authjs.dev/img/providers";
  const conditionalUIProviderID = providers.find((provider) => provider.type === "webauthn" && provider.enableConditionalUI)?.id;
  return o("div", { className: "signin", children: [theme?.brandColor && o("style", { dangerouslySetInnerHTML: {
    __html: `:root {--brand-color: ${theme.brandColor}}`
  } }), theme?.buttonText && o("style", { dangerouslySetInnerHTML: {
    __html: `
        :root {
          --button-text-color: ${theme.buttonText}
        }
      `
  } }), o("div", { className: "card", children: [error && o("div", { className: "error", children: o("p", { children: error }) }), theme?.logo && o("img", { src: theme.logo, alt: "Logo", className: "logo" }), providers.map((provider, i2) => {
    let bg, text2, logo, logoDark, bgDark, textDark;
    if (provider.type === "oauth" || provider.type === "oidc") {
      ({
        bg = "",
        text: text2 = "",
        logo = "",
        bgDark = bg,
        textDark = text2,
        logoDark = ""
      } = provider.style ?? {});
      logo = logo.startsWith("/") ? providerLogoPath + logo : logo;
      logoDark = logoDark.startsWith("/") ? providerLogoPath + logoDark : logoDark || logo;
      logoDark || (logoDark = logo);
    }
    return o("div", { className: "provider", children: [provider.type === "oauth" || provider.type === "oidc" ? o("form", { action: provider.signinUrl, method: "POST", children: [o("input", { type: "hidden", name: "csrfToken", value: csrfToken }), callbackUrl && o("input", { type: "hidden", name: "callbackUrl", value: callbackUrl }), o("button", { type: "submit", className: "button", style: {
      "--provider-bg": bg,
      "--provider-dark-bg": bgDark,
      "--provider-color": text2,
      "--provider-dark-color": textDark,
      "--provider-bg-hover": hexToRgba(bg, 0.8),
      "--provider-dark-bg-hover": hexToRgba(bgDark, 0.8)
    }, tabIndex: 0, children: [logo && o("img", { loading: "lazy", height: 24, width: 24, id: "provider-logo", src: logo }), logoDark && o("img", { loading: "lazy", height: 24, width: 24, id: "provider-logo-dark", src: logoDark }), o("span", { children: ["Sign in with ", provider.name] })] })] }) : null, (provider.type === "email" || provider.type === "credentials" || provider.type === "webauthn") && i2 > 0 && providers[i2 - 1].type !== "email" && providers[i2 - 1].type !== "credentials" && providers[i2 - 1].type !== "webauthn" && o("hr", {}), provider.type === "email" && o("form", { action: provider.signinUrl, method: "POST", children: [o("input", { type: "hidden", name: "csrfToken", value: csrfToken }), o("label", { className: "section-header", htmlFor: `input-email-for-${provider.id}-provider`, children: "Email" }), o("input", { id: `input-email-for-${provider.id}-provider`, autoFocus: true, type: "email", name: "email", value: email, placeholder: "email@example.com", required: true }), o("button", { id: "submitButton", type: "submit", tabIndex: 0, children: ["Sign in with ", provider.name] })] }), provider.type === "credentials" && o("form", { action: provider.callbackUrl, method: "POST", children: [o("input", { type: "hidden", name: "csrfToken", value: csrfToken }), Object.keys(provider.credentials).map((credential) => {
      return o("div", { children: [o("label", { className: "section-header", htmlFor: `input-${credential}-for-${provider.id}-provider`, children: provider.credentials[credential].label ?? credential }), o("input", { name: credential, id: `input-${credential}-for-${provider.id}-provider`, type: provider.credentials[credential].type ?? "text", placeholder: provider.credentials[credential].placeholder ?? "", ...provider.credentials[credential] })] }, `input-group-${provider.id}`);
    }), o("button", { id: "submitButton", type: "submit", tabIndex: 0, children: ["Sign in with ", provider.name] })] }), provider.type === "webauthn" && o("form", { action: provider.callbackUrl, method: "POST", id: `${provider.id}-form`, children: [o("input", { type: "hidden", name: "csrfToken", value: csrfToken }), Object.keys(provider.formFields).map((field) => {
      return o("div", { children: [o("label", { className: "section-header", htmlFor: `input-${field}-for-${provider.id}-provider`, children: provider.formFields[field].label ?? field }), o("input", { name: field, "data-form-field": true, id: `input-${field}-for-${provider.id}-provider`, type: provider.formFields[field].type ?? "text", placeholder: provider.formFields[field].placeholder ?? "", ...provider.formFields[field] })] }, `input-group-${provider.id}`);
    }), o("button", { id: `submitButton-${provider.id}`, type: "submit", tabIndex: 0, children: ["Sign in with ", provider.name] })] }), (provider.type === "email" || provider.type === "credentials" || provider.type === "webauthn") && i2 + 1 < providers.length && o("hr", {})] }, provider.id);
  })] }), conditionalUIProviderID && ConditionalUIScript(conditionalUIProviderID)] });
}
function SignoutPage(props) {
  const { url, csrfToken, theme } = props;
  return o("div", { className: "signout", children: [theme?.brandColor && o("style", { dangerouslySetInnerHTML: {
    __html: `
        :root {
          --brand-color: ${theme.brandColor}
        }
      `
  } }), theme?.buttonText && o("style", { dangerouslySetInnerHTML: {
    __html: `
        :root {
          --button-text-color: ${theme.buttonText}
        }
      `
  } }), o("div", { className: "card", children: [theme?.logo && o("img", { src: theme.logo, alt: "Logo", className: "logo" }), o("h1", { children: "Signout" }), o("p", { children: "Are you sure you want to sign out?" }), o("form", { action: url?.toString(), method: "POST", children: [o("input", { type: "hidden", name: "csrfToken", value: csrfToken }), o("button", { id: "submitButton", type: "submit", children: "Sign out" })] })] })] });
}
const css = `:root {
  --border-width: 1px;
  --border-radius: 0.5rem;
  --color-error: #c94b4b;
  --color-info: #157efb;
  --color-info-hover: #0f6ddb;
  --color-info-text: #fff;
}

.__next-auth-theme-auto,
.__next-auth-theme-light {
  --color-background: #ececec;
  --color-background-hover: rgba(236, 236, 236, 0.8);
  --color-background-card: #fff;
  --color-text: #000;
  --color-primary: #444;
  --color-control-border: #bbb;
  --color-button-active-background: #f9f9f9;
  --color-button-active-border: #aaa;
  --color-separator: #ccc;
}

.__next-auth-theme-dark {
  --color-background: #161b22;
  --color-background-hover: rgba(22, 27, 34, 0.8);
  --color-background-card: #0d1117;
  --color-text: #fff;
  --color-primary: #ccc;
  --color-control-border: #555;
  --color-button-active-background: #060606;
  --color-button-active-border: #666;
  --color-separator: #444;
}

@media (prefers-color-scheme: dark) {
  .__next-auth-theme-auto {
    --color-background: #161b22;
    --color-background-hover: rgba(22, 27, 34, 0.8);
    --color-background-card: #0d1117;
    --color-text: #fff;
    --color-primary: #ccc;
    --color-control-border: #555;
    --color-button-active-background: #060606;
    --color-button-active-border: #666;
    --color-separator: #444;
  }

  button,
  a.button {
    color: var(--provider-dark-color, var(--color-primary));
    background-color: var(--provider-dark-bg, var(--color-background));
  }
    :is(button,a.button):hover {
      background-color: var(
        --provider-dark-bg-hover,
        var(--color-background-hover)
      ) !important;
    }
  #provider-logo {
    display: none !important;
  }
  #provider-logo-dark {
    width: 25px;
    display: block !important;
  }
}
html {
  box-sizing: border-box;
}
*,
*:before,
*:after {
  box-sizing: inherit;
  margin: 0;
  padding: 0;
}

body {
  background-color: var(--color-background);
  margin: 0;
  padding: 0;
  font-family:
    ui-sans-serif,
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    Roboto,
    "Helvetica Neue",
    Arial,
    "Noto Sans",
    sans-serif,
    "Apple Color Emoji",
    "Segoe UI Emoji",
    "Segoe UI Symbol",
    "Noto Color Emoji";
}

h1 {
  margin-bottom: 1.5rem;
  padding: 0 1rem;
  font-weight: 400;
  color: var(--color-text);
}

p {
  margin-bottom: 1.5rem;
  padding: 0 1rem;
  color: var(--color-text);
}

form {
  margin: 0;
  padding: 0;
}

label {
  font-weight: 500;
  text-align: left;
  margin-bottom: 0.25rem;
  display: block;
  color: var(--color-text);
}

input[type] {
  box-sizing: border-box;
  display: block;
  width: 100%;
  padding: 0.5rem 1rem;
  border: var(--border-width) solid var(--color-control-border);
  background: var(--color-background-card);
  font-size: 1rem;
  border-radius: var(--border-radius);
  color: var(--color-text);
}

input[type]:focus {
    box-shadow: none;
  }

p {
  font-size: 1.1rem;
  line-height: 2rem;
}

a.button {
  text-decoration: none;
  line-height: 1rem;
}

a.button:link,
  a.button:visited {
    background-color: var(--color-background);
    color: var(--color-primary);
  }

button span {
  flex-grow: 1;
}

button,
a.button {
  padding: 0.75rem 1rem;
  color: var(--provider-color, var(--color-primary));
  background-color: var(--provider-bg);
  font-size: 1.1rem;
  min-height: 62px;
  border-color: rgba(0, 0, 0, 0.1);
  border-radius: var(--border-radius);
  transition: all 0.1s ease-in-out;
  font-weight: 500;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}

:is(button,a.button):hover {
    background-color: var(--provider-bg-hover, var(--color-background-hover));
    cursor: pointer;
  }

:is(button,a.button):active {
    cursor: pointer;
  }

:is(button,a.button) #provider-logo {
    width: 25px;
    display: block;
  }

:is(button,a.button) #provider-logo-dark {
    display: none;
  }

#submitButton {
  color: var(--button-text-color, var(--color-info-text));
  background-color: var(--brand-color, var(--color-info));
  width: 100%;
}

#submitButton:hover {
    background-color: var(
      --button-hover-bg,
      var(--color-info-hover)
    ) !important;
  }

a.site {
  color: var(--color-primary);
  text-decoration: none;
  font-size: 1rem;
  line-height: 2rem;
}

a.site:hover {
    text-decoration: underline;
  }

.page {
  position: absolute;
  width: 100%;
  height: 100%;
  display: grid;
  place-items: center;
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

.page > div {
    text-align: center;
  }

.error a.button {
    padding-left: 2rem;
    padding-right: 2rem;
    margin-top: 0.5rem;
  }

.error .message {
    margin-bottom: 1.5rem;
  }

.signin input[type="text"] {
    margin-left: auto;
    margin-right: auto;
    display: block;
  }

.signin hr {
    display: block;
    border: 0;
    border-top: 1px solid var(--color-separator);
    margin: 2rem auto 1rem auto;
    overflow: visible;
  }

.signin hr::before {
      content: "or";
      background: var(--color-background-card);
      color: #888;
      padding: 0 0.4rem;
      position: relative;
      top: -0.7rem;
    }

.signin .error {
    background: #f5f5f5;
    font-weight: 500;
    border-radius: 0.3rem;
    background: var(--color-error);
  }

.signin .error p {
      text-align: left;
      padding: 0.5rem 1rem;
      font-size: 0.9rem;
      line-height: 1.2rem;
      color: var(--color-info-text);
    }

.signin > div,
  .signin form {
    display: block;
  }

.signin > div input[type], .signin form input[type] {
      margin-bottom: 0.5rem;
    }

.signin > div button, .signin form button {
      width: 100%;
    }

.signin .provider + .provider {
    margin-top: 1rem;
  }

.logo {
  display: inline-block;
  max-width: 150px;
  margin: 1.25rem 0;
  max-height: 70px;
}

.card {
  background-color: var(--color-background-card);
  border-radius: 2rem;
  padding: 1.25rem 2rem;
}

.card .header {
    color: var(--color-primary);
  }

.section-header {
  color: var(--color-text);
}

@media screen and (min-width: 450px) {
  .card {
    margin: 2rem 0;
    width: 368px;
  }
}
@media screen and (max-width: 450px) {
  .card {
    margin: 1rem 0;
    width: 343px;
  }
}
`;
function VerifyRequestPage(props) {
  const { url, theme } = props;
  return o("div", { className: "verify-request", children: [theme.brandColor && o("style", { dangerouslySetInnerHTML: {
    __html: `
        :root {
          --brand-color: ${theme.brandColor}
        }
      `
  } }), o("div", { className: "card", children: [theme.logo && o("img", { src: theme.logo, alt: "Logo", className: "logo" }), o("h1", { children: "Check your email" }), o("p", { children: "A sign in link has been sent to your email address." }), o("p", { children: o("a", { className: "site", href: url.origin, children: url.host }) })] })] });
}
function send({ html, title, status, cookies, theme, headTags }) {
  return {
    cookies,
    status,
    headers: { "Content-Type": "text/html" },
    body: `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>${css}</style><title>${title}</title>${headTags ?? ""}</head><body class="__next-auth-theme-${theme?.colorScheme ?? "auto"}"><div class="page">${k(html)}</div></body></html>`
  };
}
function renderPage(params) {
  const { url, theme, query, cookies, pages, providers } = params;
  return {
    csrf(skip, options, cookies2) {
      if (!skip) {
        return {
          headers: { "Content-Type": "application/json" },
          body: { csrfToken: options.csrfToken },
          cookies: cookies2
        };
      }
      options.logger.warn("csrf-disabled");
      cookies2.push({
        name: options.cookies.csrfToken.name,
        value: "",
        options: { ...options.cookies.csrfToken.options, maxAge: 0 }
      });
      return { status: 404, cookies: cookies2 };
    },
    providers(providers2) {
      return {
        headers: { "Content-Type": "application/json" },
        body: providers2.reduce((acc, { id, name, type, signinUrl, callbackUrl }) => {
          acc[id] = { id, name, type, signinUrl, callbackUrl };
          return acc;
        }, {})
      };
    },
    signin(providerId, error) {
      if (providerId)
        throw new UnknownAction("Unsupported action");
      if (pages?.signIn) {
        let signinUrl = `${pages.signIn}${pages.signIn.includes("?") ? "&" : "?"}${new URLSearchParams({ callbackUrl: params.callbackUrl ?? "/" })}`;
        if (error)
          signinUrl = `${signinUrl}&${new URLSearchParams({ error })}`;
        return { redirect: signinUrl, cookies };
      }
      const webauthnProvider = providers?.find((p2) => p2.type === "webauthn" && p2.enableConditionalUI && !!p2.simpleWebAuthnBrowserVersion);
      let simpleWebAuthnBrowserScript = "";
      if (webauthnProvider) {
        const { simpleWebAuthnBrowserVersion } = webauthnProvider;
        simpleWebAuthnBrowserScript = `<script src="https://unpkg.com/@simplewebauthn/browser@${simpleWebAuthnBrowserVersion}/dist/bundle/index.umd.min.js" crossorigin="anonymous"><\/script>`;
      }
      return send({
        cookies,
        theme,
        html: SigninPage({
          csrfToken: params.csrfToken,
          // We only want to render providers
          providers: params.providers?.filter((provider) => (
            // Always render oauth and email type providers
            ["email", "oauth", "oidc"].includes(provider.type) || // Only render credentials type provider if credentials are defined
            provider.type === "credentials" && provider.credentials || // Only render webauthn type provider if formFields are defined
            provider.type === "webauthn" && provider.formFields || // Don't render other provider types
            false
          )),
          callbackUrl: params.callbackUrl,
          theme: params.theme,
          error,
          ...query
        }),
        title: "Sign In",
        headTags: simpleWebAuthnBrowserScript
      });
    },
    signout() {
      if (pages?.signOut)
        return { redirect: pages.signOut, cookies };
      return send({
        cookies,
        theme,
        html: SignoutPage({ csrfToken: params.csrfToken, url, theme }),
        title: "Sign Out"
      });
    },
    verifyRequest(props) {
      if (pages?.verifyRequest)
        return { redirect: pages.verifyRequest, cookies };
      return send({
        cookies,
        theme,
        html: VerifyRequestPage({ url, theme, ...props }),
        title: "Verify Request"
      });
    },
    error(error) {
      if (pages?.error) {
        return {
          redirect: `${pages.error}${pages.error.includes("?") ? "&" : "?"}error=${error}`,
          cookies
        };
      }
      return send({
        cookies,
        theme,
        // @ts-expect-error fix error type
        ...ErrorPage({ url, theme, error }),
        title: "Error"
      });
    }
  };
}
function fromDate(time, date = Date.now()) {
  return new Date(date + time * 1e3);
}
async function handleLoginOrRegister(sessionToken, _profile, _account, options) {
  if (!_account?.providerAccountId || !_account.type)
    throw new Error("Missing or invalid provider account");
  if (!["email", "oauth", "oidc", "webauthn"].includes(_account.type))
    throw new Error("Provider not supported");
  const { adapter, jwt: jwt2, events, session: { strategy: sessionStrategy, generateSessionToken } } = options;
  if (!adapter) {
    return { user: _profile, account: _account };
  }
  const profile = _profile;
  let account = _account;
  const { createUser, updateUser, getUser, getUserByAccount, getUserByEmail, linkAccount, createSession, getSessionAndUser, deleteSession } = adapter;
  let session2 = null;
  let user = null;
  let isNewUser = false;
  const useJwtSession = sessionStrategy === "jwt";
  if (sessionToken) {
    if (useJwtSession) {
      try {
        const salt = options.cookies.sessionToken.name;
        session2 = await jwt2.decode({ ...jwt2, token: sessionToken, salt });
        if (session2 && "sub" in session2 && session2.sub) {
          user = await getUser(session2.sub);
        }
      } catch {
      }
    } else {
      const userAndSession = await getSessionAndUser(sessionToken);
      if (userAndSession) {
        session2 = userAndSession.session;
        user = userAndSession.user;
      }
    }
  }
  if (account.type === "email") {
    const userByEmail = await getUserByEmail(profile.email);
    if (userByEmail) {
      if (user?.id !== userByEmail.id && !useJwtSession && sessionToken) {
        await deleteSession(sessionToken);
      }
      user = await updateUser({
        id: userByEmail.id,
        emailVerified: /* @__PURE__ */ new Date()
      });
      await events.updateUser?.({ user });
    } else {
      user = await createUser({ ...profile, emailVerified: /* @__PURE__ */ new Date() });
      await events.createUser?.({ user });
      isNewUser = true;
    }
    session2 = useJwtSession ? {} : await createSession({
      sessionToken: generateSessionToken(),
      userId: user.id,
      expires: fromDate(options.session.maxAge)
    });
    return { session: session2, user, isNewUser };
  } else if (account.type === "webauthn") {
    const userByAccount2 = await getUserByAccount({
      providerAccountId: account.providerAccountId,
      provider: account.provider
    });
    if (userByAccount2) {
      if (user) {
        if (userByAccount2.id === user.id) {
          const currentAccount2 = { ...account, userId: user.id };
          return { session: session2, user, isNewUser, account: currentAccount2 };
        }
        throw new AccountNotLinked("The account is already associated with another user", { provider: account.provider });
      }
      session2 = useJwtSession ? {} : await createSession({
        sessionToken: generateSessionToken(),
        userId: userByAccount2.id,
        expires: fromDate(options.session.maxAge)
      });
      const currentAccount = { ...account, userId: userByAccount2.id };
      return { session: session2, user: userByAccount2, isNewUser, account: currentAccount };
    } else {
      if (user) {
        await linkAccount({ ...account, userId: user.id });
        await events.linkAccount?.({ user, account, profile });
        const currentAccount2 = { ...account, userId: user.id };
        return { session: session2, user, isNewUser, account: currentAccount2 };
      }
      const userByEmail = profile.email ? await getUserByEmail(profile.email) : null;
      if (userByEmail) {
        throw new AccountNotLinked("Another account already exists with the same e-mail address", { provider: account.provider });
      } else {
        user = await createUser({ ...profile });
      }
      await events.createUser?.({ user });
      await linkAccount({ ...account, userId: user.id });
      await events.linkAccount?.({ user, account, profile });
      session2 = useJwtSession ? {} : await createSession({
        sessionToken: generateSessionToken(),
        userId: user.id,
        expires: fromDate(options.session.maxAge)
      });
      const currentAccount = { ...account, userId: user.id };
      return { session: session2, user, isNewUser: true, account: currentAccount };
    }
  }
  const userByAccount = await getUserByAccount({
    providerAccountId: account.providerAccountId,
    provider: account.provider
  });
  if (userByAccount) {
    if (user) {
      if (userByAccount.id === user.id) {
        return { session: session2, user, isNewUser };
      }
      throw new OAuthAccountNotLinked("The account is already associated with another user", { provider: account.provider });
    }
    session2 = useJwtSession ? {} : await createSession({
      sessionToken: generateSessionToken(),
      userId: userByAccount.id,
      expires: fromDate(options.session.maxAge)
    });
    return { session: session2, user: userByAccount, isNewUser };
  } else {
    const { provider: p2 } = options;
    const { type, provider, providerAccountId, userId, ...tokenSet } = account;
    const defaults = { providerAccountId, provider, type, userId };
    account = Object.assign(p2.account(tokenSet) ?? {}, defaults);
    if (user) {
      await linkAccount({ ...account, userId: user.id });
      await events.linkAccount?.({ user, account, profile });
      return { session: session2, user, isNewUser };
    }
    const userByEmail = profile.email ? await getUserByEmail(profile.email) : null;
    if (userByEmail) {
      const provider2 = options.provider;
      if (provider2?.allowDangerousEmailAccountLinking) {
        user = userByEmail;
      } else {
        throw new OAuthAccountNotLinked("Another account already exists with the same e-mail address", { provider: account.provider });
      }
    } else {
      user = await createUser({ ...profile, emailVerified: null });
    }
    await events.createUser?.({ user });
    await linkAccount({ ...account, userId: user.id });
    await events.linkAccount?.({ user, account, profile });
    session2 = useJwtSession ? {} : await createSession({
      sessionToken: generateSessionToken(),
      userId: user.id,
      expires: fromDate(options.session.maxAge)
    });
    return { session: session2, user, isNewUser: true };
  }
}
let USER_AGENT;
if (typeof navigator === "undefined" || !navigator.userAgent?.startsWith?.("Mozilla/5.0 ")) {
  const NAME = "oauth4webapi";
  const VERSION = "v2.10.3";
  USER_AGENT = `${NAME}/${VERSION}`;
}
function looseInstanceOf(input, expected) {
  if (input == null) {
    return false;
  }
  try {
    return input instanceof expected || Object.getPrototypeOf(input)[Symbol.toStringTag] === expected.prototype[Symbol.toStringTag];
  } catch {
    return false;
  }
}
const clockSkew = Symbol();
const clockTolerance = Symbol();
const customFetch = Symbol();
const useMtlsAlias = Symbol();
const encoder = new TextEncoder();
const decoder = new TextDecoder();
function buf(input) {
  if (typeof input === "string") {
    return encoder.encode(input);
  }
  return decoder.decode(input);
}
const CHUNK_SIZE = 32768;
function encodeBase64Url(input) {
  if (input instanceof ArrayBuffer) {
    input = new Uint8Array(input);
  }
  const arr = [];
  for (let i2 = 0; i2 < input.byteLength; i2 += CHUNK_SIZE) {
    arr.push(String.fromCharCode.apply(null, input.subarray(i2, i2 + CHUNK_SIZE)));
  }
  return btoa(arr.join("")).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function decodeBase64Url(input) {
  try {
    const binary = atob(input.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, ""));
    const bytes = new Uint8Array(binary.length);
    for (let i2 = 0; i2 < binary.length; i2++) {
      bytes[i2] = binary.charCodeAt(i2);
    }
    return bytes;
  } catch (cause) {
    throw new OPE("The input to be decoded is not correctly encoded.", { cause });
  }
}
function b64u(input) {
  if (typeof input === "string") {
    return decodeBase64Url(input);
  }
  return encodeBase64Url(input);
}
class LRU {
  constructor(maxSize) {
    this.cache = /* @__PURE__ */ new Map();
    this._cache = /* @__PURE__ */ new Map();
    this.maxSize = maxSize;
  }
  get(key) {
    let v2 = this.cache.get(key);
    if (v2) {
      return v2;
    }
    if (v2 = this._cache.get(key)) {
      this.update(key, v2);
      return v2;
    }
    return void 0;
  }
  has(key) {
    return this.cache.has(key) || this._cache.has(key);
  }
  set(key, value) {
    if (this.cache.has(key)) {
      this.cache.set(key, value);
    } else {
      this.update(key, value);
    }
    return this;
  }
  delete(key) {
    if (this.cache.has(key)) {
      return this.cache.delete(key);
    }
    if (this._cache.has(key)) {
      return this._cache.delete(key);
    }
    return false;
  }
  update(key, value) {
    this.cache.set(key, value);
    if (this.cache.size >= this.maxSize) {
      this._cache = this.cache;
      this.cache = /* @__PURE__ */ new Map();
    }
  }
}
class UnsupportedOperationError extends Error {
  constructor(message2) {
    super(message2 ?? "operation not supported");
    this.name = this.constructor.name;
    Error.captureStackTrace?.(this, this.constructor);
  }
}
class OperationProcessingError extends Error {
  constructor(message2, options) {
    super(message2, options);
    this.name = this.constructor.name;
    Error.captureStackTrace?.(this, this.constructor);
  }
}
const OPE = OperationProcessingError;
const dpopNonces = new LRU(100);
function isCryptoKey(key) {
  return key instanceof CryptoKey;
}
function isPrivateKey(key) {
  return isCryptoKey(key) && key.type === "private";
}
function isPublicKey(key) {
  return isCryptoKey(key) && key.type === "public";
}
function processDpopNonce(response) {
  try {
    const nonce2 = response.headers.get("dpop-nonce");
    if (nonce2) {
      dpopNonces.set(new URL(response.url).origin, nonce2);
    }
  } catch {
  }
  return response;
}
function isJsonObject(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return false;
  }
  return true;
}
function prepareHeaders(input) {
  if (looseInstanceOf(input, Headers)) {
    input = Object.fromEntries(input.entries());
  }
  const headers = new Headers(input);
  if (USER_AGENT && !headers.has("user-agent")) {
    headers.set("user-agent", USER_AGENT);
  }
  if (headers.has("authorization")) {
    throw new TypeError('"options.headers" must not include the "authorization" header name');
  }
  if (headers.has("dpop")) {
    throw new TypeError('"options.headers" must not include the "dpop" header name');
  }
  return headers;
}
function signal(value) {
  if (typeof value === "function") {
    value = value();
  }
  if (!(value instanceof AbortSignal)) {
    throw new TypeError('"options.signal" must return or be an instance of AbortSignal');
  }
  return value;
}
async function discoveryRequest(issuerIdentifier, options) {
  if (!(issuerIdentifier instanceof URL)) {
    throw new TypeError('"issuerIdentifier" must be an instance of URL');
  }
  if (issuerIdentifier.protocol !== "https:" && issuerIdentifier.protocol !== "http:") {
    throw new TypeError('"issuer.protocol" must be "https:" or "http:"');
  }
  const url = new URL(issuerIdentifier.href);
  switch (options?.algorithm) {
    case void 0:
    case "oidc":
      url.pathname = `${url.pathname}/.well-known/openid-configuration`.replace("//", "/");
      break;
    case "oauth2":
      if (url.pathname === "/") {
        url.pathname = ".well-known/oauth-authorization-server";
      } else {
        url.pathname = `.well-known/oauth-authorization-server/${url.pathname}`.replace("//", "/");
      }
      break;
    default:
      throw new TypeError('"options.algorithm" must be "oidc" (default), or "oauth2"');
  }
  const headers = prepareHeaders(options?.headers);
  headers.set("accept", "application/json");
  return (options?.[customFetch] || fetch)(url.href, {
    headers: Object.fromEntries(headers.entries()),
    method: "GET",
    redirect: "manual",
    signal: options?.signal ? signal(options.signal) : null
  }).then(processDpopNonce);
}
function validateString(input) {
  return typeof input === "string" && input.length !== 0;
}
async function processDiscoveryResponse(expectedIssuerIdentifier, response) {
  if (!(expectedIssuerIdentifier instanceof URL)) {
    throw new TypeError('"expectedIssuer" must be an instance of URL');
  }
  if (!looseInstanceOf(response, Response)) {
    throw new TypeError('"response" must be an instance of Response');
  }
  if (response.status !== 200) {
    throw new OPE('"response" is not a conform Authorization Server Metadata response');
  }
  assertReadableResponse(response);
  let json;
  try {
    json = await response.json();
  } catch (cause) {
    throw new OPE('failed to parse "response" body as JSON', { cause });
  }
  if (!isJsonObject(json)) {
    throw new OPE('"response" body must be a top level object');
  }
  if (!validateString(json.issuer)) {
    throw new OPE('"response" body "issuer" property must be a non-empty string');
  }
  if (new URL(json.issuer).href !== expectedIssuerIdentifier.href) {
    throw new OPE('"response" body "issuer" does not match "expectedIssuer"');
  }
  return json;
}
function randomBytes() {
  return b64u(crypto.getRandomValues(new Uint8Array(32)));
}
function generateRandomCodeVerifier() {
  return randomBytes();
}
function generateRandomState() {
  return randomBytes();
}
function generateRandomNonce() {
  return randomBytes();
}
async function calculatePKCECodeChallenge(codeVerifier) {
  if (!validateString(codeVerifier)) {
    throw new TypeError('"codeVerifier" must be a non-empty string');
  }
  return b64u(await crypto.subtle.digest("SHA-256", buf(codeVerifier)));
}
function getKeyAndKid(input) {
  if (input instanceof CryptoKey) {
    return { key: input };
  }
  if (!(input?.key instanceof CryptoKey)) {
    return {};
  }
  if (input.kid !== void 0 && !validateString(input.kid)) {
    throw new TypeError('"kid" must be a non-empty string');
  }
  return { key: input.key, kid: input.kid };
}
function formUrlEncode(token) {
  return encodeURIComponent(token).replace(/%20/g, "+");
}
function clientSecretBasic(clientId, clientSecret) {
  const username = formUrlEncode(clientId);
  const password = formUrlEncode(clientSecret);
  const credentials = btoa(`${username}:${password}`);
  return `Basic ${credentials}`;
}
function psAlg(key) {
  switch (key.algorithm.hash.name) {
    case "SHA-256":
      return "PS256";
    case "SHA-384":
      return "PS384";
    case "SHA-512":
      return "PS512";
    default:
      throw new UnsupportedOperationError("unsupported RsaHashedKeyAlgorithm hash name");
  }
}
function rsAlg(key) {
  switch (key.algorithm.hash.name) {
    case "SHA-256":
      return "RS256";
    case "SHA-384":
      return "RS384";
    case "SHA-512":
      return "RS512";
    default:
      throw new UnsupportedOperationError("unsupported RsaHashedKeyAlgorithm hash name");
  }
}
function esAlg(key) {
  switch (key.algorithm.namedCurve) {
    case "P-256":
      return "ES256";
    case "P-384":
      return "ES384";
    case "P-521":
      return "ES512";
    default:
      throw new UnsupportedOperationError("unsupported EcKeyAlgorithm namedCurve");
  }
}
function keyToJws(key) {
  switch (key.algorithm.name) {
    case "RSA-PSS":
      return psAlg(key);
    case "RSASSA-PKCS1-v1_5":
      return rsAlg(key);
    case "ECDSA":
      return esAlg(key);
    case "Ed25519":
    case "Ed448":
      return "EdDSA";
    default:
      throw new UnsupportedOperationError("unsupported CryptoKey algorithm name");
  }
}
function getClockSkew(client2) {
  const skew = client2?.[clockSkew];
  return typeof skew === "number" && Number.isFinite(skew) ? skew : 0;
}
function getClockTolerance(client2) {
  const tolerance = client2?.[clockTolerance];
  return typeof tolerance === "number" && Number.isFinite(tolerance) && Math.sign(tolerance) !== -1 ? tolerance : 30;
}
function epochTime() {
  return Math.floor(Date.now() / 1e3);
}
function clientAssertion(as, client2) {
  const now2 = epochTime() + getClockSkew(client2);
  return {
    jti: randomBytes(),
    aud: [as.issuer, as.token_endpoint],
    exp: now2 + 60,
    iat: now2,
    nbf: now2,
    iss: client2.client_id,
    sub: client2.client_id
  };
}
async function privateKeyJwt(as, client2, key, kid) {
  return jwt({
    alg: keyToJws(key),
    kid
  }, clientAssertion(as, client2), key);
}
function assertAs(as) {
  if (typeof as !== "object" || as === null) {
    throw new TypeError('"as" must be an object');
  }
  if (!validateString(as.issuer)) {
    throw new TypeError('"as.issuer" property must be a non-empty string');
  }
  return true;
}
function assertClient(client2) {
  if (typeof client2 !== "object" || client2 === null) {
    throw new TypeError('"client" must be an object');
  }
  if (!validateString(client2.client_id)) {
    throw new TypeError('"client.client_id" property must be a non-empty string');
  }
  return true;
}
function assertClientSecret(clientSecret) {
  if (!validateString(clientSecret)) {
    throw new TypeError('"client.client_secret" property must be a non-empty string');
  }
  return clientSecret;
}
function assertNoClientPrivateKey(clientAuthMethod, clientPrivateKey) {
  if (clientPrivateKey !== void 0) {
    throw new TypeError(`"options.clientPrivateKey" property must not be provided when ${clientAuthMethod} client authentication method is used.`);
  }
}
function assertNoClientSecret(clientAuthMethod, clientSecret) {
  if (clientSecret !== void 0) {
    throw new TypeError(`"client.client_secret" property must not be provided when ${clientAuthMethod} client authentication method is used.`);
  }
}
async function clientAuthentication(as, client2, body, headers, clientPrivateKey) {
  body.delete("client_secret");
  body.delete("client_assertion_type");
  body.delete("client_assertion");
  switch (client2.token_endpoint_auth_method) {
    case void 0:
    case "client_secret_basic": {
      assertNoClientPrivateKey("client_secret_basic", clientPrivateKey);
      headers.set("authorization", clientSecretBasic(client2.client_id, assertClientSecret(client2.client_secret)));
      break;
    }
    case "client_secret_post": {
      assertNoClientPrivateKey("client_secret_post", clientPrivateKey);
      body.set("client_id", client2.client_id);
      body.set("client_secret", assertClientSecret(client2.client_secret));
      break;
    }
    case "private_key_jwt": {
      assertNoClientSecret("private_key_jwt", client2.client_secret);
      if (clientPrivateKey === void 0) {
        throw new TypeError('"options.clientPrivateKey" must be provided when "client.token_endpoint_auth_method" is "private_key_jwt"');
      }
      const { key, kid } = getKeyAndKid(clientPrivateKey);
      if (!isPrivateKey(key)) {
        throw new TypeError('"options.clientPrivateKey.key" must be a private CryptoKey');
      }
      body.set("client_id", client2.client_id);
      body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      body.set("client_assertion", await privateKeyJwt(as, client2, key, kid));
      break;
    }
    case "tls_client_auth":
    case "self_signed_tls_client_auth":
    case "none": {
      assertNoClientSecret(client2.token_endpoint_auth_method, client2.client_secret);
      assertNoClientPrivateKey(client2.token_endpoint_auth_method, clientPrivateKey);
      body.set("client_id", client2.client_id);
      break;
    }
    default:
      throw new UnsupportedOperationError("unsupported client token_endpoint_auth_method");
  }
}
async function jwt(header, claimsSet, key) {
  if (!key.usages.includes("sign")) {
    throw new TypeError('CryptoKey instances used for signing assertions must include "sign" in their "usages"');
  }
  const input = `${b64u(buf(JSON.stringify(header)))}.${b64u(buf(JSON.stringify(claimsSet)))}`;
  const signature = b64u(await crypto.subtle.sign(keyToSubtle(key), key, buf(input)));
  return `${input}.${signature}`;
}
async function dpopProofJwt(headers, options, url, htm, clockSkew2, accessToken) {
  const { privateKey, publicKey, nonce: nonce2 = dpopNonces.get(url.origin) } = options;
  if (!isPrivateKey(privateKey)) {
    throw new TypeError('"DPoP.privateKey" must be a private CryptoKey');
  }
  if (!isPublicKey(publicKey)) {
    throw new TypeError('"DPoP.publicKey" must be a public CryptoKey');
  }
  if (nonce2 !== void 0 && !validateString(nonce2)) {
    throw new TypeError('"DPoP.nonce" must be a non-empty string or undefined');
  }
  if (!publicKey.extractable) {
    throw new TypeError('"DPoP.publicKey.extractable" must be true');
  }
  const now2 = epochTime() + clockSkew2;
  const proof = await jwt({
    alg: keyToJws(privateKey),
    typ: "dpop+jwt",
    jwk: await publicJwk(publicKey)
  }, {
    iat: now2,
    jti: randomBytes(),
    htm,
    nonce: nonce2,
    htu: `${url.origin}${url.pathname}`,
    ath: accessToken ? b64u(await crypto.subtle.digest("SHA-256", buf(accessToken))) : void 0
  }, privateKey);
  headers.set("dpop", proof);
}
let jwkCache;
async function getSetPublicJwkCache(key) {
  const { kty, e, n: n2, x: x2, y: y2, crv } = await crypto.subtle.exportKey("jwk", key);
  const jwk = { kty, e, n: n2, x: x2, y: y2, crv };
  jwkCache.set(key, jwk);
  return jwk;
}
async function publicJwk(key) {
  jwkCache || (jwkCache = /* @__PURE__ */ new WeakMap());
  return jwkCache.get(key) || getSetPublicJwkCache(key);
}
function validateEndpoint(value, endpoint, options) {
  if (typeof value !== "string") {
    if (options?.[useMtlsAlias]) {
      throw new TypeError(`"as.mtls_endpoint_aliases.${endpoint}" must be a string`);
    }
    throw new TypeError(`"as.${endpoint}" must be a string`);
  }
  return new URL(value);
}
function resolveEndpoint(as, endpoint, options) {
  if (options?.[useMtlsAlias] && as.mtls_endpoint_aliases && endpoint in as.mtls_endpoint_aliases) {
    return validateEndpoint(as.mtls_endpoint_aliases[endpoint], endpoint, options);
  }
  return validateEndpoint(as[endpoint], endpoint);
}
function isOAuth2Error(input) {
  const value = input;
  if (typeof value !== "object" || Array.isArray(value) || value === null) {
    return false;
  }
  return value.error !== void 0;
}
function unquote(value) {
  if (value.length >= 2 && value[0] === '"' && value[value.length - 1] === '"') {
    return value.slice(1, -1);
  }
  return value;
}
const SPLIT_REGEXP = /((?:,|, )?[0-9a-zA-Z!#$%&'*+-.^_`|~]+=)/;
const SCHEMES_REGEXP = /(?:^|, ?)([0-9a-zA-Z!#$%&'*+\-.^_`|~]+)(?=$|[ ,])/g;
function wwwAuth(scheme, params) {
  const arr = params.split(SPLIT_REGEXP).slice(1);
  if (!arr.length) {
    return { scheme: scheme.toLowerCase(), parameters: {} };
  }
  arr[arr.length - 1] = arr[arr.length - 1].replace(/,$/, "");
  const parameters = {};
  for (let i2 = 1; i2 < arr.length; i2 += 2) {
    const idx = i2;
    if (arr[idx][0] === '"') {
      while (arr[idx].slice(-1) !== '"' && ++i2 < arr.length) {
        arr[idx] += arr[i2];
      }
    }
    const key = arr[idx - 1].replace(/^(?:, ?)|=$/g, "").toLowerCase();
    parameters[key] = unquote(arr[idx]);
  }
  return {
    scheme: scheme.toLowerCase(),
    parameters
  };
}
function parseWwwAuthenticateChallenges(response) {
  if (!looseInstanceOf(response, Response)) {
    throw new TypeError('"response" must be an instance of Response');
  }
  const header = response.headers.get("www-authenticate");
  if (header === null) {
    return void 0;
  }
  const result = [];
  for (const { 1: scheme, index } of header.matchAll(SCHEMES_REGEXP)) {
    result.push([scheme, index]);
  }
  if (!result.length) {
    return void 0;
  }
  const challenges = result.map(([scheme, indexOf], i2, others) => {
    const next = others[i2 + 1];
    let parameters;
    if (next) {
      parameters = header.slice(indexOf, next[1]);
    } else {
      parameters = header.slice(indexOf);
    }
    return wwwAuth(scheme, parameters);
  });
  return challenges;
}
async function protectedResourceRequest(accessToken, method, url, headers, body, options) {
  if (!validateString(accessToken)) {
    throw new TypeError('"accessToken" must be a non-empty string');
  }
  if (!(url instanceof URL)) {
    throw new TypeError('"url" must be an instance of URL');
  }
  headers = prepareHeaders(headers);
  if (options?.DPoP === void 0) {
    headers.set("authorization", `Bearer ${accessToken}`);
  } else {
    await dpopProofJwt(headers, options.DPoP, url, "GET", getClockSkew({ [clockSkew]: options?.[clockSkew] }), accessToken);
    headers.set("authorization", `DPoP ${accessToken}`);
  }
  return (options?.[customFetch] || fetch)(url.href, {
    body,
    headers: Object.fromEntries(headers.entries()),
    method,
    redirect: "manual",
    signal: options?.signal ? signal(options.signal) : null
  }).then(processDpopNonce);
}
async function userInfoRequest(as, client2, accessToken, options) {
  assertAs(as);
  assertClient(client2);
  const url = resolveEndpoint(as, "userinfo_endpoint", options);
  const headers = prepareHeaders(options?.headers);
  if (client2.userinfo_signed_response_alg) {
    headers.set("accept", "application/jwt");
  } else {
    headers.set("accept", "application/json");
    headers.append("accept", "application/jwt");
  }
  return protectedResourceRequest(accessToken, "GET", url, headers, null, {
    ...options,
    [clockSkew]: getClockSkew(client2)
  });
}
async function authenticatedRequest(as, client2, method, url, body, headers, options) {
  await clientAuthentication(as, client2, body, headers, options?.clientPrivateKey);
  headers.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8");
  return (options?.[customFetch] || fetch)(url.href, {
    body,
    headers: Object.fromEntries(headers.entries()),
    method,
    redirect: "manual",
    signal: options?.signal ? signal(options.signal) : null
  }).then(processDpopNonce);
}
async function tokenEndpointRequest(as, client2, grantType, parameters, options) {
  const url = resolveEndpoint(as, "token_endpoint", options);
  parameters.set("grant_type", grantType);
  const headers = prepareHeaders(options?.headers);
  headers.set("accept", "application/json");
  if (options?.DPoP !== void 0) {
    await dpopProofJwt(headers, options.DPoP, url, "POST", getClockSkew(client2));
  }
  return authenticatedRequest(as, client2, "POST", url, parameters, headers, options);
}
const idTokenClaims = /* @__PURE__ */ new WeakMap();
function getValidatedIdTokenClaims(ref) {
  if (!ref.id_token) {
    return void 0;
  }
  const claims = idTokenClaims.get(ref);
  if (!claims) {
    throw new TypeError('"ref" was already garbage collected or did not resolve from the proper sources');
  }
  return claims;
}
async function processGenericAccessTokenResponse(as, client2, response, ignoreIdToken = false, ignoreRefreshToken = false) {
  assertAs(as);
  assertClient(client2);
  if (!looseInstanceOf(response, Response)) {
    throw new TypeError('"response" must be an instance of Response');
  }
  if (response.status !== 200) {
    let err;
    if (err = await handleOAuthBodyError(response)) {
      return err;
    }
    throw new OPE('"response" is not a conform Token Endpoint response');
  }
  assertReadableResponse(response);
  let json;
  try {
    json = await response.json();
  } catch (cause) {
    throw new OPE('failed to parse "response" body as JSON', { cause });
  }
  if (!isJsonObject(json)) {
    throw new OPE('"response" body must be a top level object');
  }
  if (!validateString(json.access_token)) {
    throw new OPE('"response" body "access_token" property must be a non-empty string');
  }
  if (!validateString(json.token_type)) {
    throw new OPE('"response" body "token_type" property must be a non-empty string');
  }
  json.token_type = json.token_type.toLowerCase();
  if (json.token_type !== "dpop" && json.token_type !== "bearer") {
    throw new UnsupportedOperationError("unsupported `token_type` value");
  }
  if (json.expires_in !== void 0 && (typeof json.expires_in !== "number" || json.expires_in <= 0)) {
    throw new OPE('"response" body "expires_in" property must be a positive number');
  }
  if (!ignoreRefreshToken && json.refresh_token !== void 0 && !validateString(json.refresh_token)) {
    throw new OPE('"response" body "refresh_token" property must be a non-empty string');
  }
  if (json.scope !== void 0 && typeof json.scope !== "string") {
    throw new OPE('"response" body "scope" property must be a string');
  }
  if (!ignoreIdToken) {
    if (json.id_token !== void 0 && !validateString(json.id_token)) {
      throw new OPE('"response" body "id_token" property must be a non-empty string');
    }
    if (json.id_token) {
      const { claims } = await validateJwt(json.id_token, checkSigningAlgorithm.bind(void 0, client2.id_token_signed_response_alg, as.id_token_signing_alg_values_supported), noSignatureCheck, getClockSkew(client2), getClockTolerance(client2)).then(validatePresence.bind(void 0, ["aud", "exp", "iat", "iss", "sub"])).then(validateIssuer.bind(void 0, as.issuer)).then(validateAudience.bind(void 0, client2.client_id));
      if (Array.isArray(claims.aud) && claims.aud.length !== 1 && claims.azp !== client2.client_id) {
        throw new OPE('unexpected ID Token "azp" (authorized party) claim value');
      }
      if (client2.require_auth_time && typeof claims.auth_time !== "number") {
        throw new OPE('unexpected ID Token "auth_time" (authentication time) claim value');
      }
      idTokenClaims.set(json, claims);
    }
  }
  return json;
}
function validateAudience(expected, result) {
  if (Array.isArray(result.claims.aud)) {
    if (!result.claims.aud.includes(expected)) {
      throw new OPE('unexpected JWT "aud" (audience) claim value');
    }
  } else if (result.claims.aud !== expected) {
    throw new OPE('unexpected JWT "aud" (audience) claim value');
  }
  return result;
}
function validateIssuer(expected, result) {
  if (result.claims.iss !== expected) {
    throw new OPE('unexpected JWT "iss" (issuer) claim value');
  }
  return result;
}
const branded = /* @__PURE__ */ new WeakSet();
function brand(searchParams) {
  branded.add(searchParams);
  return searchParams;
}
async function authorizationCodeGrantRequest(as, client2, callbackParameters, redirectUri, codeVerifier, options) {
  assertAs(as);
  assertClient(client2);
  if (!branded.has(callbackParameters)) {
    throw new TypeError('"callbackParameters" must be an instance of URLSearchParams obtained from "validateAuthResponse()", or "validateJwtAuthResponse()');
  }
  if (!validateString(redirectUri)) {
    throw new TypeError('"redirectUri" must be a non-empty string');
  }
  if (!validateString(codeVerifier)) {
    throw new TypeError('"codeVerifier" must be a non-empty string');
  }
  const code = getURLSearchParameter(callbackParameters, "code");
  if (!code) {
    throw new OPE('no authorization code in "callbackParameters"');
  }
  const parameters = new URLSearchParams(options?.additionalParameters);
  parameters.set("redirect_uri", redirectUri);
  parameters.set("code_verifier", codeVerifier);
  parameters.set("code", code);
  return tokenEndpointRequest(as, client2, "authorization_code", parameters, options);
}
const jwtClaimNames = {
  aud: "audience",
  c_hash: "code hash",
  client_id: "client id",
  exp: "expiration time",
  iat: "issued at",
  iss: "issuer",
  jti: "jwt id",
  nonce: "nonce",
  s_hash: "state hash",
  sub: "subject",
  ath: "access token hash",
  htm: "http method",
  htu: "http uri",
  cnf: "confirmation"
};
function validatePresence(required, result) {
  for (const claim of required) {
    if (result.claims[claim] === void 0) {
      throw new OPE(`JWT "${claim}" (${jwtClaimNames[claim]}) claim missing`);
    }
  }
  return result;
}
const expectNoNonce = Symbol();
const skipAuthTimeCheck = Symbol();
async function processAuthorizationCodeOpenIDResponse(as, client2, response, expectedNonce, maxAge) {
  const result = await processGenericAccessTokenResponse(as, client2, response);
  if (isOAuth2Error(result)) {
    return result;
  }
  if (!validateString(result.id_token)) {
    throw new OPE('"response" body "id_token" property must be a non-empty string');
  }
  maxAge ?? (maxAge = client2.default_max_age ?? skipAuthTimeCheck);
  const claims = getValidatedIdTokenClaims(result);
  if ((client2.require_auth_time || maxAge !== skipAuthTimeCheck) && claims.auth_time === void 0) {
    throw new OPE('ID Token "auth_time" (authentication time) claim missing');
  }
  if (maxAge !== skipAuthTimeCheck) {
    if (typeof maxAge !== "number" || maxAge < 0) {
      throw new TypeError('"options.max_age" must be a non-negative number');
    }
    const now2 = epochTime() + getClockSkew(client2);
    const tolerance = getClockTolerance(client2);
    if (claims.auth_time + maxAge < now2 - tolerance) {
      throw new OPE("too much time has elapsed since the last End-User authentication");
    }
  }
  switch (expectedNonce) {
    case void 0:
    case expectNoNonce:
      if (claims.nonce !== void 0) {
        throw new OPE('unexpected ID Token "nonce" claim value');
      }
      break;
    default:
      if (!validateString(expectedNonce)) {
        throw new TypeError('"expectedNonce" must be a non-empty string');
      }
      if (claims.nonce === void 0) {
        throw new OPE('ID Token "nonce" claim missing');
      }
      if (claims.nonce !== expectedNonce) {
        throw new OPE('unexpected ID Token "nonce" claim value');
      }
  }
  return result;
}
async function processAuthorizationCodeOAuth2Response(as, client2, response) {
  const result = await processGenericAccessTokenResponse(as, client2, response, true);
  if (isOAuth2Error(result)) {
    return result;
  }
  if (result.id_token !== void 0) {
    if (typeof result.id_token === "string" && result.id_token.length) {
      throw new OPE("Unexpected ID Token returned, use processAuthorizationCodeOpenIDResponse() for OpenID Connect callback processing");
    }
    delete result.id_token;
  }
  return result;
}
function assertReadableResponse(response) {
  if (response.bodyUsed) {
    throw new TypeError('"response" body has been used already');
  }
}
async function handleOAuthBodyError(response) {
  if (response.status > 399 && response.status < 500) {
    assertReadableResponse(response);
    try {
      const json = await response.json();
      if (isJsonObject(json) && typeof json.error === "string" && json.error.length) {
        if (json.error_description !== void 0 && typeof json.error_description !== "string") {
          delete json.error_description;
        }
        if (json.error_uri !== void 0 && typeof json.error_uri !== "string") {
          delete json.error_uri;
        }
        if (json.algs !== void 0 && typeof json.algs !== "string") {
          delete json.algs;
        }
        if (json.scope !== void 0 && typeof json.scope !== "string") {
          delete json.scope;
        }
        return json;
      }
    } catch {
    }
  }
  return void 0;
}
function checkRsaKeyAlgorithm(algorithm) {
  if (typeof algorithm.modulusLength !== "number" || algorithm.modulusLength < 2048) {
    throw new OPE(`${algorithm.name} modulusLength must be at least 2048 bits`);
  }
}
function ecdsaHashName(namedCurve) {
  switch (namedCurve) {
    case "P-256":
      return "SHA-256";
    case "P-384":
      return "SHA-384";
    case "P-521":
      return "SHA-512";
    default:
      throw new UnsupportedOperationError();
  }
}
function keyToSubtle(key) {
  switch (key.algorithm.name) {
    case "ECDSA":
      return {
        name: key.algorithm.name,
        hash: ecdsaHashName(key.algorithm.namedCurve)
      };
    case "RSA-PSS": {
      checkRsaKeyAlgorithm(key.algorithm);
      switch (key.algorithm.hash.name) {
        case "SHA-256":
        case "SHA-384":
        case "SHA-512":
          return {
            name: key.algorithm.name,
            saltLength: parseInt(key.algorithm.hash.name.slice(-3), 10) >> 3
          };
        default:
          throw new UnsupportedOperationError();
      }
    }
    case "RSASSA-PKCS1-v1_5":
      checkRsaKeyAlgorithm(key.algorithm);
      return key.algorithm.name;
    case "Ed448":
    case "Ed25519":
      return key.algorithm.name;
  }
  throw new UnsupportedOperationError();
}
const noSignatureCheck = Symbol();
async function validateJwt(jws, checkAlg, getKey, clockSkew2, clockTolerance2) {
  const { 0: protectedHeader, 1: payload, 2: encodedSignature, length } = jws.split(".");
  if (length === 5) {
    throw new UnsupportedOperationError("JWE structure JWTs are not supported");
  }
  if (length !== 3) {
    throw new OPE("Invalid JWT");
  }
  let header;
  try {
    header = JSON.parse(buf(b64u(protectedHeader)));
  } catch (cause) {
    throw new OPE("failed to parse JWT Header body as base64url encoded JSON", { cause });
  }
  if (!isJsonObject(header)) {
    throw new OPE("JWT Header must be a top level object");
  }
  checkAlg(header);
  if (header.crit !== void 0) {
    throw new OPE('unexpected JWT "crit" header parameter');
  }
  const signature = b64u(encodedSignature);
  let key;
  if (getKey !== noSignatureCheck) {
    key = await getKey(header);
    const input = `${protectedHeader}.${payload}`;
    const verified = await crypto.subtle.verify(keyToSubtle(key), key, signature, buf(input));
    if (!verified) {
      throw new OPE("JWT signature verification failed");
    }
  }
  let claims;
  try {
    claims = JSON.parse(buf(b64u(payload)));
  } catch (cause) {
    throw new OPE("failed to parse JWT Payload body as base64url encoded JSON", { cause });
  }
  if (!isJsonObject(claims)) {
    throw new OPE("JWT Payload must be a top level object");
  }
  const now2 = epochTime() + clockSkew2;
  if (claims.exp !== void 0) {
    if (typeof claims.exp !== "number") {
      throw new OPE('unexpected JWT "exp" (expiration time) claim type');
    }
    if (claims.exp <= now2 - clockTolerance2) {
      throw new OPE('unexpected JWT "exp" (expiration time) claim value, timestamp is <= now()');
    }
  }
  if (claims.iat !== void 0) {
    if (typeof claims.iat !== "number") {
      throw new OPE('unexpected JWT "iat" (issued at) claim type');
    }
  }
  if (claims.iss !== void 0) {
    if (typeof claims.iss !== "string") {
      throw new OPE('unexpected JWT "iss" (issuer) claim type');
    }
  }
  if (claims.nbf !== void 0) {
    if (typeof claims.nbf !== "number") {
      throw new OPE('unexpected JWT "nbf" (not before) claim type');
    }
    if (claims.nbf > now2 + clockTolerance2) {
      throw new OPE('unexpected JWT "nbf" (not before) claim value, timestamp is > now()');
    }
  }
  if (claims.aud !== void 0) {
    if (typeof claims.aud !== "string" && !Array.isArray(claims.aud)) {
      throw new OPE('unexpected JWT "aud" (audience) claim type');
    }
  }
  return { header, claims, signature, key };
}
function checkSigningAlgorithm(client2, issuer, header) {
  if (client2 !== void 0) {
    if (header.alg !== client2) {
      throw new OPE('unexpected JWT "alg" header parameter');
    }
    return;
  }
  if (Array.isArray(issuer)) {
    if (!issuer.includes(header.alg)) {
      throw new OPE('unexpected JWT "alg" header parameter');
    }
    return;
  }
  if (header.alg !== "RS256") {
    throw new OPE('unexpected JWT "alg" header parameter');
  }
}
function getURLSearchParameter(parameters, name) {
  const { 0: value, length } = parameters.getAll(name);
  if (length > 1) {
    throw new OPE(`"${name}" parameter must be provided only once`);
  }
  return value;
}
const skipStateCheck = Symbol();
const expectNoState = Symbol();
function validateAuthResponse(as, client2, parameters, expectedState) {
  assertAs(as);
  assertClient(client2);
  if (parameters instanceof URL) {
    parameters = parameters.searchParams;
  }
  if (!(parameters instanceof URLSearchParams)) {
    throw new TypeError('"parameters" must be an instance of URLSearchParams, or URL');
  }
  if (getURLSearchParameter(parameters, "response")) {
    throw new OPE('"parameters" contains a JARM response, use validateJwtAuthResponse() instead of validateAuthResponse()');
  }
  const iss = getURLSearchParameter(parameters, "iss");
  const state2 = getURLSearchParameter(parameters, "state");
  if (!iss && as.authorization_response_iss_parameter_supported) {
    throw new OPE('response parameter "iss" (issuer) missing');
  }
  if (iss && iss !== as.issuer) {
    throw new OPE('unexpected "iss" (issuer) response parameter value');
  }
  switch (expectedState) {
    case void 0:
    case expectNoState:
      if (state2 !== void 0) {
        throw new OPE('unexpected "state" response parameter encountered');
      }
      break;
    case skipStateCheck:
      break;
    default:
      if (!validateString(expectedState)) {
        throw new OPE('"expectedState" must be a non-empty string');
      }
      if (state2 === void 0) {
        throw new OPE('response parameter "state" missing');
      }
      if (state2 !== expectedState) {
        throw new OPE('unexpected "state" response parameter value');
      }
  }
  const error = getURLSearchParameter(parameters, "error");
  if (error) {
    return {
      error,
      error_description: getURLSearchParameter(parameters, "error_description"),
      error_uri: getURLSearchParameter(parameters, "error_uri")
    };
  }
  const id_token = getURLSearchParameter(parameters, "id_token");
  const token = getURLSearchParameter(parameters, "token");
  if (id_token !== void 0 || token !== void 0) {
    throw new UnsupportedOperationError("implicit and hybrid flows are not supported");
  }
  return brand(new URLSearchParams(parameters));
}
async function signCookie(type, value, maxAge, options, data) {
  const { cookies, logger: logger2 } = options;
  logger2.debug(`CREATE_${type.toUpperCase()}`, { value, maxAge });
  const expires = /* @__PURE__ */ new Date();
  expires.setTime(expires.getTime() + maxAge * 1e3);
  const token = { value };
  if (type === "state" && data)
    token.data = data;
  const name = cookies[type].name;
  return {
    name,
    value: await encode({ ...options.jwt, maxAge, token, salt: name }),
    options: { ...cookies[type].options, expires }
  };
}
const PKCE_MAX_AGE = 60 * 15;
const pkce = {
  async create(options) {
    const code_verifier = generateRandomCodeVerifier();
    const value = await calculatePKCECodeChallenge(code_verifier);
    const maxAge = PKCE_MAX_AGE;
    const cookie = await signCookie("pkceCodeVerifier", code_verifier, maxAge, options);
    return { cookie, value };
  },
  /**
   * Returns code_verifier if the provider is configured to use PKCE,
   * and clears the container cookie afterwards.
   * An error is thrown if the code_verifier is missing or invalid.
   * @see https://www.rfc-editor.org/rfc/rfc7636
   * @see https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/#pkce
   */
  async use(cookies, resCookies, options) {
    const { provider } = options;
    if (!provider?.checks?.includes("pkce"))
      return;
    const codeVerifier = cookies?.[options.cookies.pkceCodeVerifier.name];
    if (!codeVerifier)
      throw new InvalidCheck("PKCE code_verifier cookie was missing.");
    const value = await decode({
      ...options.jwt,
      token: codeVerifier,
      salt: options.cookies.pkceCodeVerifier.name
    });
    if (!value?.value)
      throw new InvalidCheck("PKCE code_verifier value could not be parsed.");
    resCookies.push({
      name: options.cookies.pkceCodeVerifier.name,
      value: "",
      options: { ...options.cookies.pkceCodeVerifier.options, maxAge: 0 }
    });
    return value.value;
  }
};
const STATE_MAX_AGE = 60 * 15;
function decodeState(value) {
  try {
    const decoder2 = new TextDecoder();
    return JSON.parse(decoder2.decode(decode$1(value)));
  } catch {
  }
}
const state = {
  async create(options, data) {
    const { provider } = options;
    if (!provider.checks.includes("state")) {
      if (data) {
        throw new InvalidCheck("State data was provided but the provider is not configured to use state.");
      }
      return;
    }
    const encodedState = encode$1(JSON.stringify({ ...data, random: generateRandomState() }));
    const maxAge = STATE_MAX_AGE;
    const cookie = await signCookie("state", encodedState, maxAge, options, data);
    return { cookie, value: encodedState };
  },
  /**
   * Returns state if the provider is configured to use state,
   * and clears the container cookie afterwards.
   * An error is thrown if the state is missing or invalid.
   * @see https://www.rfc-editor.org/rfc/rfc6749#section-10.12
   * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1
   */
  async use(cookies, resCookies, options, paramRandom) {
    const { provider } = options;
    if (!provider.checks.includes("state"))
      return;
    const state2 = cookies?.[options.cookies.state.name];
    if (!state2)
      throw new InvalidCheck("State cookie was missing.");
    const encodedState = await decode({
      ...options.jwt,
      token: state2,
      salt: options.cookies.state.name
    });
    if (!encodedState?.value)
      throw new InvalidCheck("State (cookie) value could not be parsed.");
    const decodedState = decodeState(encodedState.value);
    if (!decodedState)
      throw new InvalidCheck("State (encoded) value could not be parsed.");
    if (decodedState.random !== paramRandom)
      throw new InvalidCheck(`Random state values did not match. Expected: ${decodedState.random}. Got: ${paramRandom}`);
    resCookies.push({
      name: options.cookies.state.name,
      value: "",
      options: { ...options.cookies.state.options, maxAge: 0 }
    });
    return encodedState.value;
  }
};
const NONCE_MAX_AGE = 60 * 15;
const nonce = {
  async create(options) {
    if (!options.provider.checks.includes("nonce"))
      return;
    const value = generateRandomNonce();
    const maxAge = NONCE_MAX_AGE;
    const cookie = await signCookie("nonce", value, maxAge, options);
    return { cookie, value };
  },
  /**
   * Returns nonce if the provider is configured to use nonce,
   * and clears the container cookie afterwards.
   * An error is thrown if the nonce is missing or invalid.
   * @see https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
   * @see https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/#nonce
   */
  async use(cookies, resCookies, options) {
    const { provider } = options;
    if (!provider?.checks?.includes("nonce"))
      return;
    const nonce2 = cookies?.[options.cookies.nonce.name];
    if (!nonce2)
      throw new InvalidCheck("Nonce cookie was missing.");
    const value = await decode({
      ...options.jwt,
      token: nonce2,
      salt: options.cookies.nonce.name
    });
    if (!value?.value)
      throw new InvalidCheck("Nonce value could not be parsed.");
    resCookies.push({
      name: options.cookies.nonce.name,
      value: "",
      options: { ...options.cookies.nonce.options, maxAge: 0 }
    });
    return value.value;
  }
};
function handleState(query, provider, isOnRedirectProxy) {
  let randomState;
  let proxyRedirect;
  if (provider.redirectProxyUrl && !query?.state) {
    throw new InvalidCheck("Missing state in query, but required for redirect proxy");
  }
  const state2 = decodeState(query?.state);
  randomState = state2?.random;
  if (isOnRedirectProxy) {
    if (!state2?.origin)
      return { randomState };
    proxyRedirect = `${state2.origin}?${new URLSearchParams(query)}`;
  }
  return { randomState, proxyRedirect };
}
const WEBAUTHN_CHALLENGE_MAX_AGE = 60 * 15;
const webauthnChallenge = {
  async create(options, challenge, registerData) {
    const maxAge = WEBAUTHN_CHALLENGE_MAX_AGE;
    const data = { challenge, registerData };
    const cookie = await signCookie("webauthnChallenge", JSON.stringify(data), maxAge, options);
    return { cookie };
  },
  /**
   * Returns challenge if present,
   */
  async use(options, cookies, resCookies) {
    const challenge = cookies?.[options.cookies.webauthnChallenge.name];
    if (!challenge)
      throw new InvalidCheck("Challenge cookie missing.");
    const value = await decode({
      ...options.jwt,
      token: challenge,
      salt: options.cookies.webauthnChallenge.name
    });
    if (!value?.value)
      throw new InvalidCheck("Challenge value could not be parsed.");
    const cookie = {
      name: options.cookies.webauthnChallenge.name,
      value: "",
      options: { ...options.cookies.webauthnChallenge.options, maxAge: 0 }
    };
    resCookies.push(cookie);
    return JSON.parse(value.value);
  }
};
async function handleOAuth(query, cookies, options, randomState) {
  const { logger: logger2, provider } = options;
  let as;
  const { token, userinfo } = provider;
  if ((!token?.url || token.url.host === "authjs.dev") && (!userinfo?.url || userinfo.url.host === "authjs.dev")) {
    const issuer = new URL(provider.issuer);
    const discoveryResponse = await discoveryRequest(issuer);
    const discoveredAs = await processDiscoveryResponse(issuer, discoveryResponse);
    if (!discoveredAs.token_endpoint)
      throw new TypeError("TODO: Authorization server did not provide a token endpoint.");
    if (!discoveredAs.userinfo_endpoint)
      throw new TypeError("TODO: Authorization server did not provide a userinfo endpoint.");
    as = discoveredAs;
  } else {
    as = {
      issuer: provider.issuer ?? "https://authjs.dev",
      // TODO: review fallback issuer
      token_endpoint: token?.url.toString(),
      userinfo_endpoint: userinfo?.url.toString()
    };
  }
  const client2 = {
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
    ...provider.client
  };
  const resCookies = [];
  const state$1 = await state.use(cookies, resCookies, options, randomState);
  const codeGrantParams = validateAuthResponse(as, client2, new URLSearchParams(query), provider.checks.includes("state") ? state$1 : skipStateCheck);
  if (isOAuth2Error(codeGrantParams)) {
    const cause = { providerId: provider.id, ...codeGrantParams };
    logger2.debug("OAuthCallbackError", cause);
    throw new OAuthCallbackError("OAuth Provider returned an error", cause);
  }
  const codeVerifier = await pkce.use(cookies, resCookies, options);
  let redirect_uri = provider.callbackUrl;
  if (!options.isOnRedirectProxy && provider.redirectProxyUrl) {
    redirect_uri = provider.redirectProxyUrl;
  }
  let codeGrantResponse = await authorizationCodeGrantRequest(
    as,
    client2,
    codeGrantParams,
    redirect_uri,
    codeVerifier ?? "auth"
    // TODO: review fallback code verifier
  );
  if (provider.token?.conform) {
    codeGrantResponse = await provider.token.conform(codeGrantResponse.clone()) ?? codeGrantResponse;
  }
  let challenges;
  if (challenges = parseWwwAuthenticateChallenges(codeGrantResponse)) {
    for (const challenge of challenges) {
      console.log("challenge", challenge);
    }
    throw new Error("TODO: Handle www-authenticate challenges as needed");
  }
  let profile = {};
  let tokens;
  if (provider.type === "oidc") {
    const nonce$1 = await nonce.use(cookies, resCookies, options);
    const result = await processAuthorizationCodeOpenIDResponse(as, client2, codeGrantResponse, nonce$1 ?? expectNoNonce);
    if (isOAuth2Error(result)) {
      console.log("error", result);
      throw new Error("TODO: Handle OIDC response body error");
    }
    profile = getValidatedIdTokenClaims(result);
    tokens = result;
  } else {
    tokens = await processAuthorizationCodeOAuth2Response(as, client2, codeGrantResponse);
    if (isOAuth2Error(tokens)) {
      console.log("error", tokens);
      throw new Error("TODO: Handle OAuth 2.0 response body error");
    }
    if (userinfo?.request) {
      const _profile = await userinfo.request({ tokens, provider });
      if (_profile instanceof Object)
        profile = _profile;
    } else if (userinfo?.url) {
      const userinfoResponse = await userInfoRequest(as, client2, tokens.access_token);
      profile = await userinfoResponse.json();
    } else {
      throw new TypeError("No userinfo endpoint configured");
    }
  }
  if (tokens.expires_in) {
    tokens.expires_at = Math.floor(Date.now() / 1e3) + Number(tokens.expires_in);
  }
  const profileResult = await getUserAndAccount(profile, provider, tokens, logger2);
  return { ...profileResult, profile, cookies: resCookies };
}
async function getUserAndAccount(OAuthProfile, provider, tokens, logger2) {
  try {
    const userFromProfile = await provider.profile(OAuthProfile, tokens);
    const user = {
      ...userFromProfile,
      id: crypto.randomUUID(),
      email: userFromProfile.email?.toLowerCase()
    };
    return {
      user,
      account: {
        ...tokens,
        provider: provider.id,
        type: provider.type,
        providerAccountId: userFromProfile.id ?? crypto.randomUUID()
      }
    };
  } catch (e) {
    logger2.debug("getProfile error details", OAuthProfile);
    logger2.error(new OAuthProfileParseError(e, { provider: provider.id }));
  }
}
function inferWebAuthnOptions(action, loggedIn, userInfoResponse) {
  const { user, exists = false } = userInfoResponse ?? {};
  switch (action) {
    case "authenticate": {
      return "authenticate";
    }
    case "register": {
      if (user && loggedIn === exists)
        return "register";
      break;
    }
    case void 0: {
      if (!loggedIn) {
        if (user) {
          if (exists) {
            return "authenticate";
          } else {
            return "register";
          }
        } else {
          return "authenticate";
        }
      }
      break;
    }
  }
  return null;
}
async function getRegistrationResponse(options, request, user, resCookies) {
  const regOptions = await getRegistrationOptions(options, request, user);
  const { cookie } = await webauthnChallenge.create(options, regOptions.challenge, user);
  return {
    status: 200,
    cookies: [...resCookies ?? [], cookie],
    body: {
      action: "register",
      options: regOptions
    },
    headers: {
      "Content-Type": "application/json"
    }
  };
}
async function getAuthenticationResponse(options, request, user, resCookies) {
  const authOptions = await getAuthenticationOptions(options, request, user);
  const { cookie } = await webauthnChallenge.create(options, authOptions.challenge);
  return {
    status: 200,
    cookies: [...resCookies ?? [], cookie],
    body: {
      action: "authenticate",
      options: authOptions
    },
    headers: {
      "Content-Type": "application/json"
    }
  };
}
async function verifyAuthenticate(options, request, resCookies) {
  const { adapter, provider } = options;
  const data = request.body && typeof request.body.data === "string" ? JSON.parse(request.body.data) : void 0;
  if (!data || typeof data !== "object" || !("id" in data) || typeof data.id !== "string") {
    throw new AuthError("Invalid WebAuthn Authentication response.");
  }
  const credentialID = toBase64(fromBase64(data.id));
  const authenticator = await adapter.getAuthenticator(credentialID);
  if (!authenticator) {
    throw new AuthError(`WebAuthn authenticator not found in database: ${JSON.stringify({
      credentialID
    })}`);
  }
  const { challenge: expectedChallenge } = await webauthnChallenge.use(options, request.cookies, resCookies);
  let verification;
  try {
    const relayingParty = provider.getRelayingParty(options, request);
    verification = await provider.simpleWebAuthn.verifyAuthenticationResponse({
      ...provider.verifyAuthenticationOptions,
      expectedChallenge,
      response: data,
      authenticator: fromAdapterAuthenticator(authenticator),
      expectedOrigin: relayingParty.origin,
      expectedRPID: relayingParty.id
    });
  } catch (e) {
    throw new WebAuthnVerificationError(e);
  }
  const { verified, authenticationInfo } = verification;
  if (!verified) {
    throw new WebAuthnVerificationError("WebAuthn authentication response could not be verified.");
  }
  try {
    const { newCounter } = authenticationInfo;
    await adapter.updateAuthenticatorCounter(authenticator.credentialID, newCounter);
  } catch (e) {
    throw new AdapterError(`Failed to update authenticator counter. This may cause future authentication attempts to fail. ${JSON.stringify({
      credentialID,
      oldCounter: authenticator.counter,
      newCounter: authenticationInfo.newCounter
    })}`, e);
  }
  const account = await adapter.getAccount(authenticator.providerAccountId, provider.id);
  if (!account) {
    throw new AuthError(`WebAuthn account not found in database: ${JSON.stringify({
      credentialID,
      providerAccountId: authenticator.providerAccountId
    })}`);
  }
  const user = await adapter.getUser(account.userId);
  if (!user) {
    throw new AuthError(`WebAuthn user not found in database: ${JSON.stringify({
      credentialID,
      providerAccountId: authenticator.providerAccountId,
      userID: account.userId
    })}`);
  }
  return {
    account,
    user
  };
}
async function verifyRegister(options, request, resCookies) {
  const { provider } = options;
  const data = request.body && typeof request.body.data === "string" ? JSON.parse(request.body.data) : void 0;
  if (!data || typeof data !== "object" || !("id" in data) || typeof data.id !== "string") {
    throw new AuthError("Invalid WebAuthn Registration response.");
  }
  const { challenge: expectedChallenge, registerData: user } = await webauthnChallenge.use(options, request.cookies, resCookies);
  if (!user) {
    throw new AuthError("Missing user registration data in WebAuthn challenge cookie.");
  }
  let verification;
  try {
    const relayingParty = provider.getRelayingParty(options, request);
    verification = await provider.simpleWebAuthn.verifyRegistrationResponse({
      ...provider.verifyRegistrationOptions,
      expectedChallenge,
      response: data,
      expectedOrigin: relayingParty.origin,
      expectedRPID: relayingParty.id
    });
  } catch (e) {
    throw new WebAuthnVerificationError(e);
  }
  if (!verification.verified || !verification.registrationInfo) {
    throw new WebAuthnVerificationError("WebAuthn registration response could not be verified.");
  }
  const account = {
    providerAccountId: toBase64(verification.registrationInfo.credentialID),
    provider: options.provider.id,
    type: provider.type
  };
  const authenticator = {
    providerAccountId: account.providerAccountId,
    counter: verification.registrationInfo.counter,
    credentialID: toBase64(verification.registrationInfo.credentialID),
    credentialPublicKey: toBase64(verification.registrationInfo.credentialPublicKey),
    credentialBackedUp: verification.registrationInfo.credentialBackedUp,
    credentialDeviceType: verification.registrationInfo.credentialDeviceType,
    transports: transportsToString(data.response.transports)
  };
  return {
    user,
    account,
    authenticator
  };
}
async function getAuthenticationOptions(options, request, user) {
  const { provider, adapter } = options;
  const authenticators = user && user["id"] ? await adapter.listAuthenticatorsByUserId(user.id) : null;
  const relayingParty = provider.getRelayingParty(options, request);
  return await provider.simpleWebAuthn.generateAuthenticationOptions({
    ...provider.authenticationOptions,
    rpID: relayingParty.id,
    allowCredentials: authenticators?.map((a2) => ({
      id: fromBase64(a2.credentialID),
      type: "public-key",
      transports: stringToTransports(a2.transports)
    }))
  });
}
async function getRegistrationOptions(options, request, user) {
  const { provider, adapter } = options;
  const authenticators = user["id"] ? await adapter.listAuthenticatorsByUserId(user.id) : null;
  const userID = randomString(32);
  const relayingParty = provider.getRelayingParty(options, request);
  return await provider.simpleWebAuthn.generateRegistrationOptions({
    ...provider.registrationOptions,
    userID,
    userName: user.email,
    userDisplayName: user.name ?? void 0,
    rpID: relayingParty.id,
    rpName: relayingParty.name,
    excludeCredentials: authenticators?.map((a2) => ({
      id: fromBase64(a2.credentialID),
      type: "public-key",
      transports: stringToTransports(a2.transports)
    }))
  });
}
function assertInternalOptionsWebAuthn(options) {
  const { provider, adapter } = options;
  if (!adapter)
    throw new MissingAdapter("An adapter is required for the WebAuthn provider");
  if (!provider || provider.type !== "webauthn") {
    throw new InvalidProvider("Provider must be WebAuthn");
  }
  return { ...options, provider, adapter };
}
function fromAdapterAuthenticator(authenticator) {
  return {
    ...authenticator,
    credentialDeviceType: authenticator.credentialDeviceType,
    transports: stringToTransports(authenticator.transports),
    credentialID: fromBase64(authenticator.credentialID),
    credentialPublicKey: fromBase64(authenticator.credentialPublicKey)
  };
}
function fromBase64(base64) {
  return new Uint8Array(Buffer.from(base64, "base64"));
}
function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}
function transportsToString(transports) {
  return transports?.join(",");
}
function stringToTransports(tstring) {
  return tstring ? tstring.split(",") : void 0;
}
async function callback(request, options, sessionStore, cookies) {
  if (!options.provider)
    throw new InvalidProvider("Callback route called without provider");
  const { query, body, method, headers } = request;
  const { provider, adapter, url, callbackUrl, pages, jwt: jwt2, events, callbacks, session: { strategy: sessionStrategy, maxAge: sessionMaxAge }, logger: logger2 } = options;
  const useJwtSession = sessionStrategy === "jwt";
  try {
    if (provider.type === "oauth" || provider.type === "oidc") {
      const { proxyRedirect, randomState } = handleState(query, provider, options.isOnRedirectProxy);
      if (proxyRedirect) {
        logger2.debug("proxy redirect", { proxyRedirect, randomState });
        return { redirect: proxyRedirect };
      }
      const authorizationResult = await handleOAuth(query, request.cookies, options, randomState);
      if (authorizationResult.cookies.length) {
        cookies.push(...authorizationResult.cookies);
      }
      logger2.debug("authorization result", authorizationResult);
      const { user: userFromProvider, account, profile: OAuthProfile } = authorizationResult;
      if (!userFromProvider || !account || !OAuthProfile) {
        return { redirect: `${url}/signin`, cookies };
      }
      let userByAccount;
      if (adapter) {
        const { getUserByAccount } = adapter;
        userByAccount = await getUserByAccount({
          providerAccountId: account.providerAccountId,
          provider: provider.id
        });
      }
      const redirect2 = await handleAuthorized({
        user: userByAccount ?? userFromProvider,
        account,
        profile: OAuthProfile
      }, options);
      if (redirect2)
        return { redirect: redirect2, cookies };
      const { user, session: session2, isNewUser } = await handleLoginOrRegister(sessionStore.value, userFromProvider, account, options);
      if (useJwtSession) {
        const defaultToken = {
          name: user.name,
          email: user.email,
          picture: user.image,
          sub: user.id?.toString()
        };
        const token = await callbacks.jwt({
          token: defaultToken,
          user,
          account,
          profile: OAuthProfile,
          isNewUser,
          trigger: isNewUser ? "signUp" : "signIn"
        });
        if (token === null) {
          cookies.push(...sessionStore.clean());
        } else {
          const salt = options.cookies.sessionToken.name;
          const newToken = await jwt2.encode({ ...jwt2, token, salt });
          const cookieExpires = /* @__PURE__ */ new Date();
          cookieExpires.setTime(cookieExpires.getTime() + sessionMaxAge * 1e3);
          const sessionCookies = sessionStore.chunk(newToken, {
            expires: cookieExpires
          });
          cookies.push(...sessionCookies);
        }
      } else {
        cookies.push({
          name: options.cookies.sessionToken.name,
          value: session2.sessionToken,
          options: {
            ...options.cookies.sessionToken.options,
            expires: session2.expires
          }
        });
      }
      await events.signIn?.({
        user,
        account,
        profile: OAuthProfile,
        isNewUser
      });
      if (isNewUser && pages.newUser) {
        return {
          redirect: `${pages.newUser}${pages.newUser.includes("?") ? "&" : "?"}${new URLSearchParams({ callbackUrl })}`,
          cookies
        };
      }
      return { redirect: callbackUrl, cookies };
    } else if (provider.type === "email") {
      const token = query?.token;
      const identifier = query?.email;
      if (!token || !identifier) {
        const e = new TypeError("Missing token or email. The sign-in URL was manually opened without token/identifier or the link was not sent correctly in the email.", { cause: { hasToken: !!token, hasEmail: !!identifier } });
        e.name = "Configuration";
        throw e;
      }
      const secret = provider.secret ?? options.secret;
      const invite = await adapter.useVerificationToken({
        identifier,
        token: await createHash(`${token}${secret}`)
      });
      const hasInvite = !!invite;
      const expired = invite ? invite.expires.valueOf() < Date.now() : void 0;
      const invalidInvite = !hasInvite || expired;
      if (invalidInvite)
        throw new Verification({ hasInvite, expired });
      const user = await adapter.getUserByEmail(identifier) ?? {
        id: crypto.randomUUID(),
        email: identifier,
        emailVerified: null
      };
      const account = {
        providerAccountId: user.email,
        userId: user.id,
        type: "email",
        provider: provider.id
      };
      const redirect2 = await handleAuthorized({ user, account }, options);
      if (redirect2)
        return { redirect: redirect2, cookies };
      const { user: loggedInUser, session: session2, isNewUser } = await handleLoginOrRegister(sessionStore.value, user, account, options);
      if (useJwtSession) {
        const defaultToken = {
          name: loggedInUser.name,
          email: loggedInUser.email,
          picture: loggedInUser.image,
          sub: loggedInUser.id?.toString()
        };
        const token2 = await callbacks.jwt({
          token: defaultToken,
          user: loggedInUser,
          account,
          isNewUser,
          trigger: isNewUser ? "signUp" : "signIn"
        });
        if (token2 === null) {
          cookies.push(...sessionStore.clean());
        } else {
          const salt = options.cookies.sessionToken.name;
          const newToken = await jwt2.encode({ ...jwt2, token: token2, salt });
          const cookieExpires = /* @__PURE__ */ new Date();
          cookieExpires.setTime(cookieExpires.getTime() + sessionMaxAge * 1e3);
          const sessionCookies = sessionStore.chunk(newToken, {
            expires: cookieExpires
          });
          cookies.push(...sessionCookies);
        }
      } else {
        cookies.push({
          name: options.cookies.sessionToken.name,
          value: session2.sessionToken,
          options: {
            ...options.cookies.sessionToken.options,
            expires: session2.expires
          }
        });
      }
      await events.signIn?.({ user: loggedInUser, account, isNewUser });
      if (isNewUser && pages.newUser) {
        return {
          redirect: `${pages.newUser}${pages.newUser.includes("?") ? "&" : "?"}${new URLSearchParams({ callbackUrl })}`,
          cookies
        };
      }
      return { redirect: callbackUrl, cookies };
    } else if (provider.type === "credentials" && method === "POST") {
      const credentials = body ?? {};
      Object.entries(query ?? {}).forEach(([k2, v2]) => url.searchParams.set(k2, v2));
      const userFromAuthorize = await provider.authorize(
        credentials,
        // prettier-ignore
        new Request(url, { headers, method, body: JSON.stringify(body) })
      );
      const user = userFromAuthorize;
      if (!user)
        throw new CredentialsSignin();
      else
        user.id = user.id?.toString() ?? crypto.randomUUID();
      const account = {
        providerAccountId: user.id,
        type: "credentials",
        provider: provider.id
      };
      const redirect2 = await handleAuthorized({ user, account, credentials }, options);
      if (redirect2)
        return { redirect: redirect2, cookies };
      const defaultToken = {
        name: user.name,
        email: user.email,
        picture: user.image,
        sub: user.id
      };
      const token = await callbacks.jwt({
        token: defaultToken,
        user,
        account,
        isNewUser: false,
        trigger: "signIn"
      });
      if (token === null) {
        cookies.push(...sessionStore.clean());
      } else {
        const salt = options.cookies.sessionToken.name;
        const newToken = await jwt2.encode({ ...jwt2, token, salt });
        const cookieExpires = /* @__PURE__ */ new Date();
        cookieExpires.setTime(cookieExpires.getTime() + sessionMaxAge * 1e3);
        const sessionCookies = sessionStore.chunk(newToken, {
          expires: cookieExpires
        });
        cookies.push(...sessionCookies);
      }
      await events.signIn?.({ user, account });
      return { redirect: callbackUrl, cookies };
    } else if (provider.type === "webauthn" && method === "POST") {
      const action = request.body?.action;
      if (typeof action !== "string" || action !== "authenticate" && action !== "register") {
        throw new AuthError("Invalid action parameter");
      }
      const localOptions = assertInternalOptionsWebAuthn(options);
      let user;
      let account;
      let authenticator;
      switch (action) {
        case "authenticate": {
          const verified = await verifyAuthenticate(localOptions, request, cookies);
          user = verified.user;
          account = verified.account;
          break;
        }
        case "register": {
          const verified = await verifyRegister(options, request, cookies);
          user = verified.user;
          account = verified.account;
          authenticator = verified.authenticator;
          break;
        }
      }
      await handleAuthorized({ user, account }, options);
      const { user: loggedInUser, isNewUser, session: session2, account: currentAccount } = await handleLoginOrRegister(sessionStore.value, user, account, options);
      if (!currentAccount) {
        throw new AuthError("Error creating or finding account");
      }
      if (authenticator && loggedInUser.id) {
        await localOptions.adapter.createAuthenticator({ ...authenticator, userId: loggedInUser.id });
      }
      if (useJwtSession) {
        const defaultToken = {
          name: loggedInUser.name,
          email: loggedInUser.email,
          picture: loggedInUser.image,
          sub: loggedInUser.id?.toString()
        };
        const token = await callbacks.jwt({
          token: defaultToken,
          user: loggedInUser,
          account: currentAccount,
          isNewUser,
          trigger: isNewUser ? "signUp" : "signIn"
        });
        if (token === null) {
          cookies.push(...sessionStore.clean());
        } else {
          const salt = options.cookies.sessionToken.name;
          const newToken = await jwt2.encode({ ...jwt2, token, salt });
          const cookieExpires = /* @__PURE__ */ new Date();
          cookieExpires.setTime(cookieExpires.getTime() + sessionMaxAge * 1e3);
          const sessionCookies = sessionStore.chunk(newToken, {
            expires: cookieExpires
          });
          cookies.push(...sessionCookies);
        }
      } else {
        cookies.push({
          name: options.cookies.sessionToken.name,
          value: session2.sessionToken,
          options: {
            ...options.cookies.sessionToken.options,
            expires: session2.expires
          }
        });
      }
      await events.signIn?.({ user: loggedInUser, account: currentAccount, isNewUser });
      if (isNewUser && pages.newUser) {
        return {
          redirect: `${pages.newUser}${pages.newUser.includes("?") ? "&" : "?"}${new URLSearchParams({ callbackUrl })}`,
          cookies
        };
      }
      return { redirect: callbackUrl, cookies };
    }
    throw new InvalidProvider(`Callback for provider type (${provider.type}) is not supported`);
  } catch (e) {
    if (e instanceof AuthError)
      throw e;
    const error = new CallbackRouteError(e, { provider: provider.id });
    logger2.debug("callback route error details", { method, query, body });
    throw error;
  }
}
async function handleAuthorized(params, config) {
  let authorized;
  const { signIn: signIn2, redirect: redirect2 } = config.callbacks;
  try {
    authorized = await signIn2(params);
  } catch (e) {
    if (e instanceof AuthError)
      throw e;
    throw new AccessDenied(e);
  }
  if (!authorized)
    throw new AccessDenied("AccessDenied");
  if (typeof authorized !== "string")
    return;
  return await redirect2({ url: authorized, baseUrl: config.url.origin });
}
async function session(options, sessionStore, cookies, isUpdate, newSession) {
  const { adapter, jwt: jwt2, events, callbacks, logger: logger2, session: { strategy: sessionStrategy, maxAge: sessionMaxAge } } = options;
  const response = {
    body: null,
    headers: { "Content-Type": "application/json" },
    cookies
  };
  const sessionToken = sessionStore.value;
  if (!sessionToken)
    return response;
  if (sessionStrategy === "jwt") {
    try {
      const salt = options.cookies.sessionToken.name;
      const payload = await jwt2.decode({ ...jwt2, token: sessionToken, salt });
      if (!payload)
        throw new Error("Invalid JWT");
      const token = await callbacks.jwt({
        token: payload,
        ...isUpdate && { trigger: "update" },
        session: newSession
      });
      const newExpires = fromDate(sessionMaxAge);
      if (token !== null) {
        const session2 = {
          user: { name: token.name, email: token.email, image: token.picture },
          expires: newExpires.toISOString()
        };
        const newSession2 = await callbacks.session({ session: session2, token });
        response.body = newSession2;
        const newToken = await jwt2.encode({ ...jwt2, token, salt });
        const sessionCookies = sessionStore.chunk(newToken, {
          expires: newExpires
        });
        response.cookies?.push(...sessionCookies);
        await events.session?.({ session: newSession2, token });
      } else {
        response.cookies?.push(...sessionStore.clean());
      }
    } catch (e) {
      logger2.error(new JWTSessionError(e));
      response.cookies?.push(...sessionStore.clean());
    }
    return response;
  }
  try {
    const { getSessionAndUser, deleteSession, updateSession } = adapter;
    let userAndSession = await getSessionAndUser(sessionToken);
    if (userAndSession && userAndSession.session.expires.valueOf() < Date.now()) {
      await deleteSession(sessionToken);
      userAndSession = null;
    }
    if (userAndSession) {
      const { user, session: session2 } = userAndSession;
      const sessionUpdateAge = options.session.updateAge;
      const sessionIsDueToBeUpdatedDate = session2.expires.valueOf() - sessionMaxAge * 1e3 + sessionUpdateAge * 1e3;
      const newExpires = fromDate(sessionMaxAge);
      if (sessionIsDueToBeUpdatedDate <= Date.now()) {
        await updateSession({
          sessionToken,
          expires: newExpires
        });
      }
      const sessionPayload = await callbacks.session({
        // TODO: user already passed below,
        // remove from session object in https://github.com/nextauthjs/next-auth/pull/9702
        // @ts-expect-error
        session: { ...session2, user },
        user,
        newSession,
        ...isUpdate ? { trigger: "update" } : {}
      });
      response.body = sessionPayload;
      response.cookies?.push({
        name: options.cookies.sessionToken.name,
        value: sessionToken,
        options: {
          ...options.cookies.sessionToken.options,
          expires: newExpires
        }
      });
      await events.session?.({ session: sessionPayload });
    } else if (sessionToken) {
      response.cookies?.push(...sessionStore.clean());
    }
  } catch (e) {
    logger2.error(new SessionTokenError(e));
  }
  return response;
}
async function getAuthorizationUrl(query, options) {
  const { logger: logger2, provider } = options;
  let url = provider.authorization?.url;
  if (!url || url.host === "authjs.dev") {
    const issuer = new URL(provider.issuer);
    const discoveryResponse = await discoveryRequest(issuer);
    const as = await processDiscoveryResponse(issuer, discoveryResponse);
    if (!as.authorization_endpoint) {
      throw new TypeError("Authorization server did not provide an authorization endpoint.");
    }
    url = new URL(as.authorization_endpoint);
  }
  const authParams = url.searchParams;
  let redirect_uri = provider.callbackUrl;
  let data;
  if (!options.isOnRedirectProxy && provider.redirectProxyUrl) {
    redirect_uri = provider.redirectProxyUrl;
    data = { origin: provider.callbackUrl };
    logger2.debug("using redirect proxy", { redirect_uri, data });
  }
  const params = Object.assign({
    response_type: "code",
    // clientId can technically be undefined, should we check this in assert.ts or rely on the Authorization Server to do it?
    client_id: provider.clientId,
    redirect_uri,
    // @ts-expect-error TODO:
    ...provider.authorization?.params
  }, Object.fromEntries(provider.authorization?.url.searchParams ?? []), query);
  for (const k2 in params)
    authParams.set(k2, params[k2]);
  const cookies = [];
  const state$1 = await state.create(options, data);
  if (state$1) {
    authParams.set("state", state$1.value);
    cookies.push(state$1.cookie);
  }
  if (provider.checks?.includes("pkce")) {
    {
      const { value, cookie } = await pkce.create(options);
      authParams.set("code_challenge", value);
      authParams.set("code_challenge_method", "S256");
      cookies.push(cookie);
    }
  }
  const nonce$1 = await nonce.create(options);
  if (nonce$1) {
    authParams.set("nonce", nonce$1.value);
    cookies.push(nonce$1.cookie);
  }
  if (provider.type === "oidc" && !url.searchParams.has("scope")) {
    url.searchParams.set("scope", "openid profile email");
  }
  logger2.debug("authorization url is ready", { url, cookies, provider });
  return { redirect: url.toString(), cookies };
}
async function sendToken(request, options) {
  const { body } = request;
  const { provider, callbacks, adapter } = options;
  const normalizer = provider.normalizeIdentifier ?? defaultNormalizer;
  const email = normalizer(body?.email);
  const defaultUser = { id: crypto.randomUUID(), email, emailVerified: null };
  const user = await adapter.getUserByEmail(email) ?? defaultUser;
  const account = {
    providerAccountId: email,
    userId: user.id,
    type: "email",
    provider: provider.id
  };
  let authorized;
  try {
    authorized = await callbacks.signIn({
      user,
      account,
      email: { verificationRequest: true }
    });
  } catch (e) {
    throw new AccessDenied(e);
  }
  if (!authorized)
    throw new AccessDenied("AccessDenied");
  if (typeof authorized === "string") {
    return {
      redirect: await callbacks.redirect({
        url: authorized,
        baseUrl: options.url.origin
      })
    };
  }
  const { callbackUrl, theme } = options;
  const token = await provider.generateVerificationToken?.() ?? randomString(32);
  const ONE_DAY_IN_SECONDS = 86400;
  const expires = new Date(Date.now() + (provider.maxAge ?? ONE_DAY_IN_SECONDS) * 1e3);
  const secret = provider.secret ?? options.secret;
  const baseUrl = new URL(options.basePath, options.url.origin);
  const sendRequest = provider.sendVerificationRequest({
    identifier: email,
    token,
    expires,
    url: `${baseUrl}/callback/${provider.id}?${new URLSearchParams({
      callbackUrl,
      token,
      email
    })}`,
    provider,
    theme,
    request: toRequest(request)
  });
  const createToken = adapter.createVerificationToken?.({
    identifier: email,
    token: await createHash(`${token}${secret}`),
    expires
  });
  await Promise.all([sendRequest, createToken]);
  return {
    redirect: `${baseUrl}/verify-request?${new URLSearchParams({
      provider: provider.id,
      type: provider.type
    })}`
  };
}
function defaultNormalizer(email) {
  if (!email)
    throw new Error("Missing email from request body.");
  let [local, domain] = email.toLowerCase().trim().split("@");
  domain = domain.split(",")[0];
  return `${local}@${domain}`;
}
async function signIn$2(request, cookies, options) {
  const signInUrl = `${options.url.origin}${options.basePath}/signin`;
  if (!options.provider)
    return { redirect: signInUrl, cookies };
  switch (options.provider.type) {
    case "oauth":
    case "oidc": {
      const { redirect: redirect2, cookies: authCookies } = await getAuthorizationUrl(request.query, options);
      if (authCookies)
        cookies.push(...authCookies);
      return { redirect: redirect2, cookies };
    }
    case "email": {
      const response = await sendToken(request, options);
      return { ...response, cookies };
    }
    default:
      return { redirect: signInUrl, cookies };
  }
}
async function signOut$2(cookies, sessionStore, options) {
  const { jwt: jwt2, events, callbackUrl: redirect2, logger: logger2, session: session2 } = options;
  const sessionToken = sessionStore.value;
  if (!sessionToken)
    return { redirect: redirect2, cookies };
  try {
    if (session2.strategy === "jwt") {
      const salt = options.cookies.sessionToken.name;
      const token = await jwt2.decode({ ...jwt2, token: sessionToken, salt });
      await events.signOut?.({ token });
    } else {
      const session3 = await options.adapter?.deleteSession(sessionToken);
      await events.signOut?.({ session: session3 });
    }
  } catch (e) {
    logger2.error(new SignOutError(e));
  }
  cookies.push(...sessionStore.clean());
  return { redirect: redirect2, cookies };
}
async function getLoggedInUser(options, sessionStore) {
  const { adapter, jwt: jwt2, session: { strategy: sessionStrategy } } = options;
  const sessionToken = sessionStore.value;
  if (!sessionToken)
    return null;
  if (sessionStrategy === "jwt") {
    const salt = options.cookies.sessionToken.name;
    const payload = await jwt2.decode({ ...jwt2, token: sessionToken, salt });
    if (payload && payload.sub) {
      return {
        id: payload.sub,
        name: payload.name,
        email: payload.email,
        image: payload.picture
      };
    }
  } else {
    const userAndSession = await adapter?.getSessionAndUser(sessionToken);
    if (userAndSession) {
      return userAndSession.user;
    }
  }
  return null;
}
async function webAuthnOptions(request, options, sessionStore, cookies) {
  const narrowOptions = assertInternalOptionsWebAuthn(options);
  const { provider } = narrowOptions;
  const { action } = request.query ?? {};
  if (action !== "register" && action !== "authenticate" && typeof action !== "undefined") {
    return {
      status: 400,
      body: { error: "Invalid action" },
      cookies,
      headers: {
        "Content-Type": "application/json"
      }
    };
  }
  const sessionUser = await getLoggedInUser(options, sessionStore);
  const getUserInfoResponse = sessionUser ? {
    user: sessionUser,
    exists: true
  } : await provider.getUserInfo(options, request);
  const userInfo = getUserInfoResponse?.user;
  const decision = inferWebAuthnOptions(action, !!sessionUser, getUserInfoResponse);
  switch (decision) {
    case "authenticate":
      return getAuthenticationResponse(narrowOptions, request, userInfo, cookies);
    case "register":
      if (typeof userInfo?.email === "string") {
        return getRegistrationResponse(narrowOptions, request, userInfo, cookies);
      }
    default:
      return {
        status: 400,
        body: { error: "Invalid request" },
        cookies,
        headers: {
          "Content-Type": "application/json"
        }
      };
  }
}
async function AuthInternal(request, authOptions) {
  const { action, providerId, error, method } = request;
  const csrfDisabled = authOptions.skipCSRFCheck === skipCSRFCheck;
  const { options, cookies } = await init({
    authOptions,
    action,
    providerId,
    url: request.url,
    callbackUrl: request.body?.callbackUrl ?? request.query?.callbackUrl,
    csrfToken: request.body?.csrfToken,
    cookies: request.cookies,
    isPost: method === "POST",
    csrfDisabled
  });
  const sessionStore = new SessionStore(options.cookies.sessionToken, request.cookies, options.logger);
  if (method === "GET") {
    const render = renderPage({ ...options, query: request.query, cookies });
    switch (action) {
      case "callback":
        return await callback(request, options, sessionStore, cookies);
      case "csrf":
        return render.csrf(csrfDisabled, options, cookies);
      case "error":
        return render.error(error);
      case "providers":
        return render.providers(options.providers);
      case "session":
        return await session(options, sessionStore, cookies);
      case "signin":
        return render.signin(providerId, error);
      case "signout":
        return render.signout();
      case "verify-request":
        return render.verifyRequest();
      case "webauthn-options":
        return await webAuthnOptions(request, options, sessionStore, cookies);
    }
  } else {
    const { csrfTokenVerified } = options;
    switch (action) {
      case "callback":
        if (options.provider.type === "credentials")
          validateCSRF(action, csrfTokenVerified);
        return await callback(request, options, sessionStore, cookies);
      case "session":
        validateCSRF(action, csrfTokenVerified);
        return await session(options, sessionStore, cookies, true, request.body?.data);
      case "signin":
        validateCSRF(action, csrfTokenVerified);
        return await signIn$2(request, cookies, options);
      case "signout":
        validateCSRF(action, csrfTokenVerified);
        return await signOut$2(cookies, sessionStore, options);
    }
  }
  throw new UnknownAction(`Cannot handle action: ${action}`);
}
const skipCSRFCheck = Symbol("skip-csrf-check");
const raw = Symbol("return-type-raw");
function setEnvDefaults$1(envObject, config) {
  try {
    const url = envObject.AUTH_URL;
    if (url && !config.basePath)
      config.basePath = new URL(url).pathname;
  } catch {
  } finally {
    config.basePath ?? (config.basePath = `/auth`);
  }
  if (!config.secret?.length) {
    config.secret = [];
    const secret = envObject.AUTH_SECRET;
    if (secret)
      config.secret.push(secret);
    for (const i2 of [1, 2, 3]) {
      const secret2 = envObject[`AUTH_SECRET_${i2}`];
      if (secret2)
        config.secret.unshift(secret2);
    }
  }
  config.redirectProxyUrl ?? (config.redirectProxyUrl = envObject.AUTH_REDIRECT_PROXY_URL);
  config.trustHost ?? (config.trustHost = !!(envObject.AUTH_URL ?? envObject.AUTH_TRUST_HOST ?? envObject.VERCEL ?? envObject.CF_PAGES ?? envObject.NODE_ENV !== "production"));
  config.providers = config.providers.map((p2) => {
    const finalProvider = typeof p2 === "function" ? p2({}) : p2;
    const ID = finalProvider.id.toUpperCase();
    if (finalProvider.type === "oauth" || finalProvider.type === "oidc") {
      finalProvider.clientId ?? (finalProvider.clientId = envObject[`AUTH_${ID}_ID`]);
      finalProvider.clientSecret ?? (finalProvider.clientSecret = envObject[`AUTH_${ID}_SECRET`]);
      if (finalProvider.type === "oidc") {
        finalProvider.issuer ?? (finalProvider.issuer = envObject[`AUTH_${ID}_ISSUER`]);
      }
    } else if (finalProvider.type === "email") {
      finalProvider.apiKey ?? (finalProvider.apiKey = envObject[`AUTH_${ID}_KEY`]);
    }
    return finalProvider;
  });
}
async function Auth(request, config) {
  setLogger(config.logger, config.debug);
  const internalRequest = await toInternalRequest(request, config);
  if (!internalRequest)
    return Response.json(`Bad request.`, { status: 400 });
  const warningsOrError = assertConfig(internalRequest, config);
  if (Array.isArray(warningsOrError)) {
    warningsOrError.forEach(logger.warn);
  } else if (warningsOrError) {
    logger.error(warningsOrError);
    const htmlPages = /* @__PURE__ */ new Set([
      "signin",
      "signout",
      "error",
      "verify-request"
    ]);
    if (!htmlPages.has(internalRequest.action) || internalRequest.method !== "GET") {
      const message2 = "There was a problem with the server configuration. Check the server logs for more information.";
      return Response.json({ message: message2 }, { status: 500 });
    }
    const { pages, theme } = config;
    const authOnErrorPage = pages?.error && internalRequest.url.searchParams.get("callbackUrl")?.startsWith(pages.error);
    if (!pages?.error || authOnErrorPage) {
      if (authOnErrorPage) {
        logger.error(new ErrorPageLoop(`The error page ${pages?.error} should not require authentication`));
      }
      const page = renderPage({ theme }).error("Configuration");
      return toResponse(page);
    }
    return Response.redirect(`${pages.error}?error=Configuration`);
  }
  const isRedirect = request.headers?.has("X-Auth-Return-Redirect");
  const isRaw = config.raw === raw;
  try {
    const internalResponse = await AuthInternal(internalRequest, config);
    if (isRaw)
      return internalResponse;
    const response = toResponse(internalResponse);
    const url = response.headers.get("Location");
    if (!isRedirect || !url)
      return response;
    return Response.json({ url }, { headers: response.headers });
  } catch (e) {
    const error = e;
    logger.error(error);
    const isAuthError = error instanceof AuthError;
    if (isAuthError && isRaw && !isRedirect)
      throw error;
    if (request.method === "POST" && internalRequest.action === "session")
      return Response.json(null, { status: 400 });
    const isClientSafeErrorType = isClientError(error);
    const type = isClientSafeErrorType ? error.type : "Configuration";
    const params = new URLSearchParams({ error: type });
    if (error instanceof CredentialsSignin)
      params.set("code", error.code);
    const pageKind = isAuthError && error.kind || "error";
    const pagePath = config.pages?.[pageKind] ?? `/${pageKind.toLowerCase()}`;
    const url = `${internalRequest.url.origin}${config.basePath}${pagePath}?${params}`;
    if (isRedirect)
      return Response.json({ url });
    return Response.redirect(url);
  }
}
function setEnvDefaults(envObject, config) {
  if (building)
    return;
  setEnvDefaults$1(envObject, config);
  config.trustHost ??= dev;
  config.basePath = `${base}/auth`;
}
async function signIn$1(provider, options = {}, authorizationParams, config, event) {
  const { request } = event;
  const headers = new Headers(request.headers);
  const { redirect: shouldRedirect = true, redirectTo, ...rest } = options instanceof FormData ? Object.fromEntries(options) : options;
  const callbackUrl = redirectTo?.toString() ?? headers.get("Referer") ?? "/";
  const base2 = createActionURL("signin", headers, config.basePath);
  if (!provider) {
    const url2 = `${base2}?${new URLSearchParams({ callbackUrl })}`;
    if (shouldRedirect)
      redirect(302, url2);
    return url2;
  }
  let url = `${base2}/${provider}?${new URLSearchParams(authorizationParams)}`;
  let foundProvider = void 0;
  for (const _provider of config.providers) {
    const { id } = typeof _provider === "function" ? _provider() : _provider;
    if (id === provider) {
      foundProvider = id;
      break;
    }
  }
  if (!foundProvider) {
    const url2 = `${base2}?${new URLSearchParams({ callbackUrl })}`;
    if (shouldRedirect)
      redirect(302, url2);
    return url2;
  }
  if (foundProvider === "credentials") {
    url = url.replace("signin", "callback");
  }
  headers.set("Content-Type", "application/x-www-form-urlencoded");
  const body = new URLSearchParams({ ...rest, callbackUrl });
  const req = new Request(url, { method: "POST", headers, body });
  const res = await Auth(req, { ...config, raw, skipCSRFCheck });
  for (const c2 of res?.cookies ?? []) {
    event.cookies.set(c2.name, c2.value, { path: "/", ...c2.options });
  }
  if (shouldRedirect) {
    return redirect(302, res.redirect);
  }
  return res.redirect;
}
async function signOut$1(options, config, event) {
  const { request } = event;
  const headers = new Headers(request.headers);
  headers.set("Content-Type", "application/x-www-form-urlencoded");
  const url = createActionURL("signout", headers, config.basePath);
  const callbackUrl = options?.redirectTo ?? headers.get("Referer") ?? "/";
  const body = new URLSearchParams({ callbackUrl });
  const req = new Request(url, { method: "POST", headers, body });
  const res = await Auth(req, { ...config, raw, skipCSRFCheck });
  for (const c2 of res?.cookies ?? [])
    event.cookies.set(c2.name, c2.value, { path: "/", ...c2.options });
  if (options?.redirect ?? true)
    return redirect(302, res.redirect);
  return res;
}
async function auth(event, config) {
  setEnvDefaults(private_env, config);
  config.trustHost ??= true;
  const { request: req } = event;
  const sessionUrl = createActionURL("session", req.headers, config.basePath);
  const request = new Request(sessionUrl, {
    headers: { cookie: req.headers.get("cookie") ?? "" }
  });
  const response = await Auth(request, config);
  const authCookies = parse_1$1(response.headers.getSetCookie());
  for (const cookie of authCookies) {
    const { name, value, ...options } = cookie;
    event.cookies.set(name, value, { path: "/", ...options });
  }
  const { status = 200 } = response;
  const data = await response.json();
  if (!data || !Object.keys(data).length)
    return null;
  if (status === 200)
    return data;
  throw new Error(data.message);
}
function createActionURL(action, headers, basePath) {
  let url = private_env.AUTH_URL;
  if (!url) {
    const host = headers.get("x-forwarded-host") ?? headers.get("host");
    const proto = headers.get("x-forwarded-proto");
    url = `${proto === "http" || dev ? "http" : "https"}://${host}${basePath}`;
  }
  return new URL(`${url.replace(/\/$/, "")}/${action}`);
}
const authorizationParamsPrefix = "authorizationParams-";
function SvelteKitAuth(config) {
  return {
    signIn: async (event) => {
      const { request } = event;
      const _config = typeof config === "object" ? config : await config(event);
      setEnvDefaults(private_env, _config);
      const formData = await request.formData();
      const { providerId: provider, ...options } = Object.fromEntries(formData);
      let authorizationParams = {};
      let _options = {};
      for (const key in options) {
        if (key.startsWith(authorizationParamsPrefix)) {
          authorizationParams[key.slice(authorizationParamsPrefix.length)] = options[key];
        } else {
          _options[key] = options[key];
        }
      }
      await signIn$1(provider, _options, authorizationParams, _config, event);
    },
    signOut: async (event) => {
      const _config = typeof config === "object" ? config : await config(event);
      setEnvDefaults(private_env, _config);
      const options = Object.fromEntries(await event.request.formData());
      await signOut$1(options, _config, event);
    },
    async handle({ event, resolve }) {
      const _config = typeof config === "object" ? config : await config(event);
      setEnvDefaults(private_env, _config);
      const { url, request } = event;
      event.locals.auth ??= () => auth(event, _config);
      event.locals.getSession ??= event.locals.auth;
      const action = url.pathname.slice(
        // @ts-expect-error - basePath is defined in setEnvDefaults
        _config.basePath.length + 1
      ).split("/")[0];
      if (isAuthAction(action) && url.pathname.startsWith(_config.basePath + "/")) {
        return Auth(request, _config);
      }
      return resolve(event);
    }
  };
}
function GitHub(config) {
  const baseUrl = config?.enterprise?.baseUrl ?? "https://github.com";
  const apiBaseUrl = config?.enterprise?.baseUrl ? `${config?.enterprise?.baseUrl}/api/v3` : "https://api.github.com";
  return {
    id: "github",
    name: "GitHub",
    type: "oauth",
    authorization: {
      url: `${baseUrl}/login/oauth/authorize`,
      params: { scope: "read:user user:email" }
    },
    token: `${baseUrl}/login/oauth/access_token`,
    userinfo: {
      url: `${apiBaseUrl}/user`,
      async request({ tokens, provider }) {
        const profile = await fetch(provider.userinfo?.url, {
          headers: {
            Authorization: `Bearer ${tokens.access_token}`,
            "User-Agent": "authjs"
          }
        }).then(async (res) => await res.json());
        if (!profile.email) {
          const res = await fetch(`${apiBaseUrl}/user/emails`, {
            headers: {
              Authorization: `Bearer ${tokens.access_token}`,
              "User-Agent": "authjs"
            }
          });
          if (res.ok) {
            const emails = await res.json();
            profile.email = (emails.find((e) => e.primary) ?? emails[0]).email;
          }
        }
        return profile;
      }
    },
    profile(profile) {
      return {
        id: profile.id.toString(),
        name: profile.name ?? profile.login,
        email: profile.email,
        image: profile.avatar_url
      };
    },
    style: { logo: "/github.svg", bg: "#24292f", text: "#fff" },
    options: config
  };
}
const AUTH_GITHUB_ID = "2b7cb1c3800eaab7a5fa";
const AUTH_GITHUB_SECRET = "80b6f5fc0fc9d0b14d6b3d5577cb19d974510fa6";
const AUTH_SECRET = "zXJK4knVoXkZQQSnTjuuvS7hxxo3c2AHejVKc3cOAnw=";
const DB_TURSO_CONNECTION_URL = "libsql://berserk-mmmoli.turso.io";
const DB_TURSO_AUTH_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3MTEzMTA1ODgsImlkIjoiMWM1NDUxNDYtOTYwOC00MDEyLTg3NWYtOWU1MjIyNDY5NTQ3In0.FeXBlqPWQTTFTIjeBNy7CcY4ivxOxOpxIM3sO8Nc1gDpi1i1OlfQFic2os67XfKxRMHAIl05I4E_81V68rIlDQ";
const users = sqliteTable("user", {
  id: text("id").notNull().primaryKey(),
  name: text("name"),
  email: text("email").notNull(),
  emailVerified: integer("emailVerified", { mode: "timestamp_ms" }),
  image: text("image")
});
const accounts = sqliteTable(
  "account",
  {
    userId: text("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
    type: text("type").$type().notNull(),
    provider: text("provider").notNull(),
    providerAccountId: text("providerAccountId").notNull(),
    refresh_token: text("refresh_token"),
    access_token: text("access_token"),
    expires_at: integer("expires_at"),
    token_type: text("token_type"),
    scope: text("scope"),
    id_token: text("id_token"),
    session_state: text("session_state")
  },
  (account) => ({
    compoundKey: primaryKey({
      columns: [account.provider, account.providerAccountId]
    })
  })
);
const sessions = sqliteTable("session", {
  sessionToken: text("sessionToken").notNull().primaryKey(),
  userId: text("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  expires: integer("expires", { mode: "timestamp_ms" }).notNull()
});
const verificationTokens = sqliteTable(
  "verificationToken",
  {
    identifier: text("identifier").notNull(),
    token: text("token").notNull(),
    expires: integer("expires", { mode: "timestamp_ms" }).notNull()
  },
  (vt) => ({
    compoundKey: primaryKey({ columns: [vt.identifier, vt.token] })
  })
);
const authSchema = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  accounts,
  sessions,
  users,
  verificationTokens
}, Symbol.toStringTag, { value: "Module" }));
const schema = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  auth: authSchema
}, Symbol.toStringTag, { value: "Module" }));
const client = createClient({
  url: DB_TURSO_CONNECTION_URL,
  authToken: DB_TURSO_AUTH_TOKEN
});
const db = drizzle(client, { schema });
const { handle, signIn, signOut } = SvelteKitAuth({
  adapter: DrizzleAdapter(db),
  providers: [GitHub({ clientId: AUTH_GITHUB_ID, clientSecret: AUTH_GITHUB_SECRET })],
  secret: AUTH_SECRET,
  pages: {
    signIn: route("/app")
  }
});
export {
  signOut as a,
  handle as h,
  signIn as s
};
