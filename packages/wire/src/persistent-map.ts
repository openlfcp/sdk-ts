/**
 * An immutable map from strings with structural sharing: `set` copies
 * only the path to the changed key (a hash array mapped trie, 32-way, at
 * most seven levels over a 32-bit hash), so the states a chain keeps for
 * every head share all untouched entries. Retaining N states that each
 * add one entry costs O(N log N) nodes instead of the N(N+1)/2 entries of
 * a full copy per state (review of #8, R8-1).
 *
 * Keys of Control State are hex IDs of SHA-256 outputs, so the hash is
 * spread; equal 32-bit hashes share a bucket compared by key. Iteration
 * order follows the hash, not insertion: no Control State rule depends on
 * the order of its maps.
 */

interface Leaf<V> {
  readonly hash: number;
  readonly key: string;
  readonly value: V;
}

/** Leaves of one full 32-bit hash, in insertion order. */
interface Bucket<V> {
  readonly branch: false;
  readonly hash: number;
  readonly leaves: readonly Leaf<V>[];
}

interface Branch<V> {
  readonly branch: true;
  readonly bitmap: number;
  readonly children: readonly Node<V>[];
}

type Node<V> = Branch<V> | Bucket<V>;

const BITS = 5;
const WIDTH_MASK = 31;
/** Below this shift a node branches on the hash; at it, equal hashes share a bucket. */
const MAX_SHIFT = 30;

/**
 * FNV-1a over the length and at most the first and the last eight UTF-16
 * code units, then the murmur3 finalizer. The keys here are hex IDs, or
 * two of them joined, so both ends are spread; equal hashes still compare
 * by key.
 */
function hashOf(key: string): number {
  const n = key.length;
  let h = Math.imul(0x811c9dc5 ^ n, 0x01000193);
  const head = n < 16 ? n : 8;
  for (let i = 0; i < head; i++) {
    h ^= key.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  for (let i = n < 16 ? n : n - 8; i < n; i++) {
    h ^= key.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h >>> 0;
}

function popcount(x: number): number {
  let v = x - ((x >>> 1) & 0x55555555);
  v = (v & 0x33333333) + ((v >>> 2) & 0x33333333);
  v = (v + (v >>> 4)) & 0x0f0f0f0f;
  return Math.imul(v, 0x01010101) >>> 24;
}

function bucket<V>(hash: number, leaves: readonly Leaf<V>[]): Bucket<V> {
  return Object.freeze({ branch: false, hash, leaves: Object.freeze(leaves) });
}

function branch<V>(bitmap: number, children: readonly Node<V>[]): Branch<V> {
  return Object.freeze({ branch: true, bitmap, children: Object.freeze(children) });
}

/** A node holding the buckets `a` and `b` of different hashes, from `shift` on. */
function split<V>(a: Bucket<V>, b: Bucket<V>, shift: number): Node<V> {
  const ia = (a.hash >>> shift) & WIDTH_MASK;
  const ib = (b.hash >>> shift) & WIDTH_MASK;
  if (ia === ib) return branch(1 << ia, [split(a, b, shift + BITS)]);
  return branch((1 << ia) | (1 << ib), ia < ib ? [a, b] : [b, a]);
}

function lookup<V>(node: Node<V> | undefined, hash: number, key: string): Leaf<V> | undefined {
  let n = node;
  let shift = 0;
  while (n !== undefined) {
    if (!n.branch) {
      if (n.hash !== hash) return undefined;
      for (const l of n.leaves) if (l.key === key) return l;
      return undefined;
    }
    const bit = 1 << ((hash >>> shift) & WIDTH_MASK);
    if ((n.bitmap & bit) === 0) return undefined;
    n = n.children[popcount(n.bitmap & (bit - 1))];
    shift += BITS;
  }
  return undefined;
}

/** `node` with `leaf` set; the second element is whether the key is new. */
function insert<V>(
  node: Node<V> | undefined,
  leaf: Leaf<V>,
  shift: number,
): readonly [Node<V>, boolean] {
  if (node === undefined) return [bucket(leaf.hash, [leaf]), true];
  if (!node.branch) {
    if (node.hash === leaf.hash) {
      const at = node.leaves.findIndex((l) => l.key === leaf.key);
      if (at < 0) return [bucket(leaf.hash, [...node.leaves, leaf]), true];
      const leaves = node.leaves.slice();
      leaves[at] = leaf;
      return [bucket(leaf.hash, leaves), false];
    }
    return [split(node, bucket(leaf.hash, [leaf]), shift), true];
  }
  if (shift > MAX_SHIFT) throw new Error("persistent map: branch below the last hash bit");
  const bit = 1 << ((leaf.hash >>> shift) & WIDTH_MASK);
  const at = popcount(node.bitmap & (bit - 1));
  const children = node.children.slice();
  if ((node.bitmap & bit) === 0) {
    children.splice(at, 0, bucket(leaf.hash, [leaf]));
    return [branch(node.bitmap | bit, children), true];
  }
  const [child, added] = insert(node.children[at], leaf, shift + BITS);
  children[at] = child;
  return [branch(node.bitmap, children), added];
}

/** `pick` of every leaf under `node`, appended to `out`. */
function collect<V, T>(node: Node<V> | undefined, pick: (l: Leaf<V>) => T, out: T[]): T[] {
  if (node === undefined) return out;
  if (!node.branch) {
    for (const l of node.leaves) out.push(pick(l));
    return out;
  }
  for (const child of node.children) collect(child, pick, out);
  return out;
}

const pickEntry = <V>(l: Leaf<V>): [string, V] => [l.key, l.value];
const pickKey = <V>(l: Leaf<V>): string => l.key;
const pickValue = <V>(l: Leaf<V>): V => l.value;

export class PersistentMap<V> implements ReadonlyMap<string, V> {
  static readonly #EMPTY = new PersistentMap<never>(undefined, 0);

  readonly #root: Node<V> | undefined;
  readonly size: number;

  private constructor(root: Node<V> | undefined, size: number) {
    this.#root = root;
    this.size = size;
    Object.freeze(this);
  }

  static empty<V>(): PersistentMap<V> {
    return PersistentMap.#EMPTY;
  }

  static from<V>(entries: Iterable<readonly [string, V]>): PersistentMap<V> {
    let map = PersistentMap.empty<V>();
    for (const [k, v] of entries) map = map.set(k, v);
    return map;
  }

  get(key: string): V | undefined {
    return lookup(this.#root, hashOf(key), key)?.value;
  }

  has(key: string): boolean {
    return lookup(this.#root, hashOf(key), key) !== undefined;
  }

  /** A map with `key` set to `value`; this one is unchanged. */
  set(key: string, value: V): PersistentMap<V> {
    const [root, added] = insert(this.#root, Object.freeze({ hash: hashOf(key), key, value }), 0);
    return new PersistentMap(root, added ? this.size + 1 : this.size);
  }

  entries(): ArrayIterator<[string, V]> {
    return collect(this.#root, pickEntry, []).values();
  }

  keys(): ArrayIterator<string> {
    return collect(this.#root, pickKey, []).values();
  }

  values(): ArrayIterator<V> {
    return collect(this.#root, pickValue, []).values();
  }

  [Symbol.iterator](): ArrayIterator<[string, V]> {
    return this.entries();
  }

  forEach(fn: (value: V, key: string, map: ReadonlyMap<string, V>) => void, thisArg?: unknown) {
    for (const [k, v] of this.entries()) fn.call(thisArg, v, k, this);
  }
}

/**
 * `map` with `key` set to `value`, sharing structure when `map` is
 * persistent; any other ReadonlyMap (a state built by a caller) is copied
 * once into a persistent one.
 */
export function put<V>(map: ReadonlyMap<string, V>, key: string, value: V): PersistentMap<V> {
  return (map instanceof PersistentMap ? map : PersistentMap.from(map)).set(key, value);
}
