// Strict Ed25519 (LFCP-WIRE-01 §10.5.1) vectors. Every edge case is named
// and kept as hex in this one file so the set can be exported as vectors.

/** RFC 8032 §7.1 test vectors (an external standard). */
export const RFC8032 = {
  TEST_1: {
    secretKey: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    publicKey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    message: "",
    signature:
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  },
  TEST_2: {
    secretKey: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    publicKey: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    message: "72",
    signature:
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  },
  TEST_3: {
    secretKey: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    publicKey: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    message: "af82",
    signature:
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  },
  TEST_SHA_ABC: {
    secretKey: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    publicKey: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    message:
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    signature:
      "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
  },
} as const;

/** Point encodings that rules 2 and 3 refuse. */
export const BAD_POINTS = {
  /** y = p + 1, a non-canonical encoding of the neutral element (y ≥ p, rule 2). */
  Y_GE_P: "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  /** y = 1 (x = 0) with the sign bit set (rule 2). */
  X0_SIGN_BIT: "0100000000000000000000000000000000000000000000000000000000000080",
  /** The neutral element (order 1, rule 3). */
  SMALL_ORDER_IDENTITY: "0100000000000000000000000000000000000000000000000000000000000000",
  /** y = p − 1, the point of order 2 (rule 3). */
  SMALL_ORDER_2: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  /** y = 0, a point of order 4 (rule 3). */
  SMALL_ORDER_4: "0000000000000000000000000000000000000000000000000000000000000000",
  /** A point of order 8 (rule 3). */
  SMALL_ORDER_8: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
} as const;

/** y = 2: y < p, but no x satisfies the curve equation (off-curve). */
export const OFF_CURVE = "0200000000000000000000000000000000000000000000000000000000000000";

/** The group order L, little-endian. */
export const L_LE = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

/** Constructed signatures that noble's (cofactored) verify accepts and §10.5.1 rejects. */
export const CONSTRUCTED = {
  /**
   * A = [a]B + T8 (a mixed-order key, not itself small-order), R = [r]B,
   * S = r + k·a with k mod 8 ≠ 0: the cofactored equation holds, the
   * cofactorless one (rule 4) does not.
   */
  MIXED_ORDER_A: {
    publicKey: "df631b69abead1f01a821d3924490bbc8934dd067537b00afd038cb0e98701d3",
    message: "6d697865642d6f726465722030",
    signature:
      "d26703e41c1ce4a720da2fb853c13b7d568a3f93c4a41df55554e59be395291b831edbdc69b2dd24324a3f1a1669696787f9660173253a52e42fc3aaa95b2e0e",
  },
  /**
   * R = the neutral element and S = k·a: both equations hold; only the
   * small-order rule (rule 3) refuses it.
   */
  SMALL_ORDER_R: {
    publicKey: "1119cc864ef1146b3654b6feb1d3bfed7e323920e8fb47874d7d711d09cb3e3d",
    message: "736d616c6c2d6f726465722052",
    signature:
      "010000000000000000000000000000000000000000000000000000000000000064889286fb79d180af8808c4f760895f6ffd89dc74bad3c9a688b7ea2c714708",
  },
  /**
   * R = [r]B + T8 (a mixed-order R, not itself small-order), A = [a]B,
   * S = r + k·a: the cofactored equation holds, the cofactorless one
   * (rule 4) does not.
   */
  MIXED_ORDER_R: {
    publicKey: "13d8f24cc1b3b79dc1fd45f1fb775325eceee920716bc5315135512c96ac4962",
    message: "6d697865642d6f726465722052",
    signature:
      "64eb9807c12088fa3e745acc456832fffd53b45b251b66bdee2af5353fc84e59ad12de9e8c520cdcff30c9b91f2dc576d7b35dbc7f37fe1f9d917388a40ee304",
  },
} as const;
