/**
 * Client simulation module.
 *
 * Probes the target TLS endpoint imitating a set of real-world clients, mirroring the
 * "Simulations" section from SSLLabs and the `run_client_simulation` function in testssl.sh.
 *
 * Each entry in CLIENT_PROFILES declares:
 *   - `name`         : human-readable client label
 *   - `minVersion`   : lowest TLS version the client will accept
 *   - `maxVersion`   : highest TLS version the client will accept
 *   - `ciphers`      : OpenSSL cipher-string (TLS 1.0-1.2)
 *   - `tls13Suites`  : TLS 1.3 cipher suite list (may be empty to mimic clients without TLS 1.3)
 *   - `sigAlgs`      : signature algorithms the client advertises
 *   - `curves`       : elliptic curves in priority order (empty = no curve extension)
 *   - `alpn`         : ALPN protocols (empty = no ALPN extension)
 */

import tls from 'node:tls';
import type { ClientSimulationResult } from '../types/index.js';

interface ClientProfile {
  name: string;
  minVersion: tls.SecureVersion;
  maxVersion: tls.SecureVersion;
  ciphers: string;
  tls13Suites: string;
  curves: string;
  alpn: string[];
}

/**
 * Client profiles sourced from:
 *   - SSLLabs Handshake Simulation lists (https://www.ssllabs.com/ssltest)
 *   - testssl.sh clientsimulation.txt (https://github.com/testssl/testssl.sh)
 *   - Firefox/Chrome/Safari public TLS configuration documentation
 *
 * The cipher strings are expressed as OpenSSL cipher names to match what Node.js /
 * OpenSSL negotiate on a real handshake.  Where a client supports TLS 1.3, the
 * tls13Suites field is populated; where it does not, tls13Suites is empty and
 * maxVersion is capped at TLSv1.2.
 */
const CLIENT_PROFILES: ClientProfile[] = [
  // ── Android ──────────────────────────────────────────────────────────────
  {
    name: 'Android 7.0',
    minVersion: 'TLSv1',
    maxVersion: 'TLSv1.2',
    ciphers: [
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES128-SHA',
      'ECDHE-ECDSA-AES256-SHA',
      'ECDHE-RSA-AES128-SHA',
      'ECDHE-RSA-AES256-SHA',
      'AES128-GCM-SHA256',
      'AES256-GCM-SHA384',
      'AES128-SHA',
      'AES256-SHA',
      'DES-CBC3-SHA',
    ].join(':'),
    tls13Suites: '',
    curves: 'X25519:secp256r1:secp384r1',
    alpn: ['http/1.1'],
  },
  {
    name: 'Android 8.1',
    minVersion: 'TLSv1',
    maxVersion: 'TLSv1.2',
    ciphers: [
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES128-SHA',
      'ECDHE-ECDSA-AES256-SHA',
      'ECDHE-RSA-AES128-SHA',
      'ECDHE-RSA-AES256-SHA',
      'AES128-GCM-SHA256',
      'AES256-GCM-SHA384',
      'AES128-SHA',
      'AES256-SHA',
    ].join(':'),
    tls13Suites: '',
    curves: 'X25519:secp256r1:secp384r1',
    alpn: ['http/1.1'],
  },
  {
    name: 'Android 9.0',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES128-SHA',
      'ECDHE-RSA-AES128-SHA',
      'AES128-GCM-SHA256',
      'AES256-GCM-SHA384',
      'AES128-SHA',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1',
    alpn: ['h2', 'http/1.1'],
  },
  {
    name: 'Android 11',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'AES128-GCM-SHA256',
      'AES256-GCM-SHA384',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1:secp521r1',
    alpn: ['h2', 'http/1.1'],
  },
  {
    name: 'Android 13',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'AES128-GCM-SHA256',
      'AES256-GCM-SHA384',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1',
    alpn: ['h2', 'http/1.1'],
  },
  // ── Apple / Safari / iOS ─────────────────────────────────────────────────
  {
    name: 'Apple ATS (iOS 9)',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
    ciphers: [
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-SHA384',
      'ECDHE-ECDSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-RSA-AES128-SHA256',
    ].join(':'),
    tls13Suites: '',
    curves: 'secp256r1:secp384r1:secp521r1',
    alpn: ['h2', 'http/1.1'],
  },
  {
    name: 'Safari 12.1 / iOS 12',
    minVersion: 'TLSv1',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES128-SHA256',
      'ECDHE-ECDSA-AES256-SHA384',
      'ECDHE-RSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-ECDSA-AES128-SHA',
      'ECDHE-ECDSA-AES256-SHA',
      'ECDHE-RSA-AES128-SHA',
      'ECDHE-RSA-AES256-SHA',
      'AES128-GCM-SHA256',
      'AES256-GCM-SHA384',
      'AES128-SHA256',
      'AES256-SHA256',
      'AES128-SHA',
      'AES256-SHA',
      'DES-CBC3-SHA',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1:secp521r1',
    alpn: ['h2', 'http/1.1'],
  },
  {
    name: 'Safari 15.4 / iOS 15',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES256-SHA384',
      'ECDHE-ECDSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-RSA-AES128-SHA256',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1:secp521r1',
    alpn: ['h2', 'http/1.1'],
  },
  {
    name: 'Safari 17 / iOS 17',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES256-SHA384',
      'ECDHE-ECDSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-RSA-AES128-SHA256',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1',
    alpn: ['h2', 'http/1.1'],
  },
  // ── Google Chrome ────────────────────────────────────────────────────────
  {
    name: 'Chrome 70 / Win 10',
    minVersion: 'TLSv1',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-RSA-AES128-SHA',
      'ECDHE-RSA-AES256-SHA',
      'AES128-GCM-SHA256',
      'AES256-GCM-SHA384',
      'AES128-SHA',
      'AES256-SHA',
      'DES-CBC3-SHA',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1',
    alpn: ['h2', 'http/1.1'],
  },
  {
    name: 'Chrome 99 / Win 10',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-RSA-AES128-SHA',
      'ECDHE-RSA-AES256-SHA',
      'AES128-GCM-SHA256',
      'AES256-GCM-SHA384',
      'AES128-SHA',
      'AES256-SHA',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1',
    alpn: ['h2', 'http/1.1'],
  },
  {
    name: 'Chrome 120 / Win 11',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-RSA-AES128-SHA',
      'ECDHE-RSA-AES256-SHA',
      'AES128-GCM-SHA256',
      'AES256-GCM-SHA384',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1',
    alpn: ['h2', 'http/1.1'],
  },
  // ── Mozilla Firefox ──────────────────────────────────────────────────────
  {
    name: 'Firefox 66 / Win 10',
    minVersion: 'TLSv1',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES256-SHA384',
      'ECDHE-ECDSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-RSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA',
      'ECDHE-RSA-AES128-SHA',
      'ECDHE-ECDSA-AES256-SHA',
      'ECDHE-ECDSA-AES128-SHA',
      'AES256-SHA',
      'AES128-SHA',
      'DES-CBC3-SHA',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1:secp521r1',
    alpn: ['h2', 'http/1.1'],
  },
  {
    name: 'Firefox 105 / Win 10',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES256-SHA384',
      'ECDHE-ECDSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-RSA-AES128-SHA256',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1:secp521r1',
    alpn: ['h2', 'http/1.1'],
  },
  {
    name: 'Firefox 121 / Win 11',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES256-SHA384',
      'ECDHE-ECDSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-RSA-AES128-SHA256',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1:secp521r1',
    alpn: ['h2', 'http/1.1'],
  },
  // ── Microsoft Internet Explorer / Edge ───────────────────────────────────
  {
    name: 'IE 11 / Win 10',
    minVersion: 'TLSv1',
    maxVersion: 'TLSv1.2',
    ciphers: [
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-RSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA',
      'ECDHE-RSA-AES128-SHA',
      'AES256-GCM-SHA384',
      'AES128-GCM-SHA256',
      'AES256-SHA256',
      'AES128-SHA256',
      'AES256-SHA',
      'AES128-SHA',
      'DES-CBC3-SHA',
    ].join(':'),
    tls13Suites: '',
    curves: 'secp256r1:secp384r1',
    alpn: [],
  },
  {
    name: 'Edge 18 / Win 10 (Legacy)',
    minVersion: 'TLSv1',
    maxVersion: 'TLSv1.2',
    ciphers: [
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-RSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA',
      'ECDHE-RSA-AES128-SHA',
      'AES256-GCM-SHA384',
      'AES128-GCM-SHA256',
      'AES256-SHA256',
      'AES128-SHA256',
      'AES256-SHA',
      'AES128-SHA',
      'DES-CBC3-SHA',
    ].join(':'),
    tls13Suites: '',
    curves: 'secp256r1:secp384r1:secp521r1',
    alpn: ['h2', 'http/1.1'],
  },
  {
    name: 'Edge 120 (Chromium) / Win 11',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-RSA-AES128-SHA',
      'ECDHE-RSA-AES256-SHA',
      'AES128-GCM-SHA256',
      'AES256-GCM-SHA384',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1',
    alpn: ['h2', 'http/1.1'],
  },
  // ── Java ─────────────────────────────────────────────────────────────────
  {
    name: 'Java 8u161',
    minVersion: 'TLSv1',
    maxVersion: 'TLSv1.2',
    ciphers: [
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-SHA384',
      'ECDHE-ECDSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-RSA-AES128-SHA256',
      'ECDHE-ECDSA-AES256-SHA',
      'ECDHE-ECDSA-AES128-SHA',
      'ECDHE-RSA-AES256-SHA',
      'ECDHE-RSA-AES128-SHA',
      'AES256-GCM-SHA384',
      'AES128-GCM-SHA256',
      'AES256-SHA256',
      'AES128-SHA256',
      'AES256-SHA',
      'AES128-SHA',
      'DES-CBC3-SHA',
    ].join(':'),
    tls13Suites: '',
    curves: 'secp256r1:secp384r1:secp521r1',
    alpn: [],
  },
  {
    name: 'Java 11',
    minVersion: 'TLSv1',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES256-SHA384',
      'ECDHE-ECDSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-RSA-AES128-SHA256',
      'ECDHE-RSA-AES256-SHA',
      'ECDHE-RSA-AES128-SHA',
      'AES256-GCM-SHA384',
      'AES128-GCM-SHA256',
      'AES256-SHA256',
      'AES128-SHA256',
      'AES256-SHA',
      'AES128-SHA',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1:secp521r1',
    alpn: [],
  },
  {
    name: 'Java 17',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'DHE-RSA-AES256-GCM-SHA384',
      'DHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-SHA384',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-ECDSA-AES128-SHA256',
      'ECDHE-RSA-AES128-SHA256',
      'AES256-GCM-SHA384',
      'AES128-GCM-SHA256',
    ].join(':'),
    tls13Suites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    curves: 'X25519:secp256r1:secp384r1:secp521r1',
    alpn: [],
  },
  // ── OpenSSL ───────────────────────────────────────────────────────────────
  {
    name: 'OpenSSL 1.1.1 (default)',
    minVersion: 'TLSv1',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'DHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'DHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'DHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-SHA384',
      'ECDHE-RSA-AES256-SHA384',
      'DHE-RSA-AES256-SHA256',
      'ECDHE-ECDSA-AES128-SHA256',
      'ECDHE-RSA-AES128-SHA256',
      'DHE-RSA-AES128-SHA256',
      'ECDHE-ECDSA-AES256-SHA',
      'ECDHE-RSA-AES256-SHA',
      'DHE-RSA-AES256-SHA',
      'ECDHE-ECDSA-AES128-SHA',
      'ECDHE-RSA-AES128-SHA',
      'DHE-RSA-AES128-SHA',
      'AES256-GCM-SHA384',
      'AES128-GCM-SHA256',
      'AES256-SHA256',
      'AES128-SHA256',
      'AES256-SHA',
      'AES128-SHA',
    ].join(':'),
    tls13Suites: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256',
    curves: 'X25519:secp256r1:secp384r1:secp521r1',
    alpn: [],
  },
  {
    name: 'OpenSSL 3.x (default)',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'DHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'DHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'DHE-RSA-AES128-GCM-SHA256',
      'AES256-GCM-SHA384',
      'AES128-GCM-SHA256',
    ].join(':'),
    tls13Suites: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256',
    curves: 'X25519:secp256r1:secp384r1:secp521r1',
    alpn: [],
  },
  // ── Curl ─────────────────────────────────────────────────────────────────
  {
    name: 'curl 7.88 / OpenSSL',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'DHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'DHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'DHE-RSA-AES128-GCM-SHA256',
    ].join(':'),
    tls13Suites: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256',
    curves: 'X25519:secp256r1:secp384r1',
    alpn: ['h2', 'http/1.1'],
  },
];

/** Detect whether a negotiated cipher provides forward secrecy. */
function detectForwardSecrecy(cipherName: string | null | undefined): boolean {
  if (!cipherName) return false;
  // ECDHE, DHE, and TLS 1.3 built-in key exchange all provide FS.
  return /ECDHE|DHE|TLS_AES|TLS_CHACHA20/i.test(cipherName);
}

/**
 * Simulate a single client connecting to the target TLS endpoint.
 * Returns negotiated protocol + cipher via Node.js native TLS (which uses OpenSSL
 * under the hood and honours the cipher-priority we specify here).
 */
async function simulateClient(
  profile: ClientProfile,
  host: string,
  port: number,
  servername: string,
  timeoutMs: number,
): Promise<ClientSimulationResult> {
  return new Promise((resolve) => {
    const opts: tls.ConnectionOptions = {
      host,
      port,
      servername,
      minVersion: profile.minVersion,
      maxVersion: profile.maxVersion,
      ciphers: profile.ciphers || undefined,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    };

    if (profile.tls13Suites) {
      // Node ≥ 12 exposes cipherSuites for TLS 1.3
      (opts as Record<string, unknown>)['cipherSuites'] = profile.tls13Suites;
    }

    if (profile.alpn.length > 0) {
      opts.ALPNProtocols = profile.alpn;
    }

    if (profile.curves) {
      (opts as Record<string, unknown>)['ecdhCurve'] = profile.curves;
    }

    const socket = tls.connect(opts);
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve({
          client: profile.name,
          protocol: null,
          cipher: null,
          forwardSecrecy: null,
          status: 'WARN',
          evidence: 'Connection timed out',
        });
      }
    }, timeoutMs + 200);

    socket.once('secureConnect', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);

      const negotiatedProtocol = socket.getProtocol() ?? null;
      const cipherInfo = socket.getCipher();
      const negotiatedCipher = cipherInfo?.standardName ?? cipherInfo?.name ?? null;
      const fs = detectForwardSecrecy(negotiatedCipher);

      socket.destroy();
      resolve({
        client: profile.name,
        protocol: negotiatedProtocol,
        cipher: negotiatedCipher,
        forwardSecrecy: fs,
        status: 'PASS',
        evidence: `Negotiated ${negotiatedProtocol ?? 'UNKNOWN'} / ${negotiatedCipher ?? 'UNKNOWN'}; FS=${fs ? 'yes' : 'no'}`,
      });
    });

    socket.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();

      const msg = err.message.toLowerCase();
      const handshakeRejected = msg.includes('handshake failure')
        || msg.includes('alert handshake failure')
        || msg.includes('unsupported protocol')
        || msg.includes('no protocols available');

      resolve({
        client: profile.name,
        protocol: null,
        cipher: null,
        forwardSecrecy: null,
        status: handshakeRejected ? 'FAIL' : 'WARN',
        evidence: handshakeRejected ? `Handshake rejected: ${err.message}` : `Connection error: ${err.message}`,
      });
    });
  });
}

/**
 * Run all client simulations sequentially (to avoid flooding the target with parallel
 * connections) and return an ordered list of results.
 */
export async function runClientSimulations(
  host: string,
  port: number,
  servername: string,
  timeoutMs = 8_000,
): Promise<ClientSimulationResult[]> {
  const results: ClientSimulationResult[] = [];

  for (const profile of CLIENT_PROFILES) {
    const result = await simulateClient(profile, host, port, servername, timeoutMs);
    results.push(result);
  }

  return results;
}

