import { CipherSuite } from "hpke";
import { KEM_DHKEM_X25519_HKDF_SHA256 } from "@panva/hpke-noble";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";

export const suite = [CipherSuite, KEM_DHKEM_X25519_HKDF_SHA256, chacha20poly1305];
