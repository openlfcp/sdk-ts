/**
 * An immutable map from strings with structural sharing: a persistent AVL
 * tree ordered by the full key. `set` copies only the nodes on the path
 * to its key (at most about 1.44 log2 n of them) and rebalances there, so
 * the states a chain keeps for every head share all untouched entries
 * (review of #8, R8-1).
 *
 * Keys are compared whole: no hash, no bucket, so no choice of keys (an
 * arbitrary device ID in a pre-emptive revocation, for example) can make
 * an update copy more than one path (review of #8, R8-1b). Iteration is
 * in ascending key order (UTF-16 code units).
 */

interface Node<V> {
  readonly key: string;
  readonly value: V;
  readonly left: Node<V> | undefined;
  readonly right: Node<V> | undefined;
  readonly height: number;
}

const heightOf = <V>(n: Node<V> | undefined): number => (n === undefined ? 0 : n.height);

function node<V>(
  key: string,
  value: V,
  left: Node<V> | undefined,
  right: Node<V> | undefined,
): Node<V> {
  const height = 1 + Math.max(heightOf(left), heightOf(right));
  return Object.freeze({ key, value, left, right, height });
}

/** A node for (key, value) over `left` and `right`, whose heights differ by at most two. */
function balanced<V>(
  key: string,
  value: V,
  left: Node<V> | undefined,
  right: Node<V> | undefined,
): Node<V> {
  const hl = heightOf(left);
  const hr = heightOf(right);
  if (hl > hr + 1) {
    const l = left as Node<V>;
    if (heightOf(l.left) >= heightOf(l.right))
      return node(l.key, l.value, l.left, node(key, value, l.right, right));
    const lr = l.right as Node<V>;
    return node(
      lr.key,
      lr.value,
      node(l.key, l.value, l.left, lr.left),
      node(key, value, lr.right, right),
    );
  }
  if (hr > hl + 1) {
    const r = right as Node<V>;
    if (heightOf(r.right) >= heightOf(r.left))
      return node(r.key, r.value, node(key, value, left, r.left), r.right);
    const rl = r.left as Node<V>;
    return node(
      rl.key,
      rl.value,
      node(key, value, left, rl.left),
      node(r.key, r.value, rl.right, r.right),
    );
  }
  return node(key, value, left, right);
}

/** `n` with `key` set; the second element is whether the key is new. */
function insert<V>(n: Node<V> | undefined, key: string, value: V): readonly [Node<V>, boolean] {
  if (n === undefined) return [node(key, value, undefined, undefined), true];
  if (key < n.key) {
    const [left, added] = insert(n.left, key, value);
    return [balanced(n.key, n.value, left, n.right), added];
  }
  if (key > n.key) {
    const [right, added] = insert(n.right, key, value);
    return [balanced(n.key, n.value, n.left, right), added];
  }
  return [node(key, value, n.left, n.right), false];
}

function lookup<V>(root: Node<V> | undefined, key: string): Node<V> | undefined {
  let n = root;
  while (n !== undefined) {
    if (key < n.key) n = n.left;
    else if (key > n.key) n = n.right;
    else return n;
  }
  return undefined;
}

/** `pick` of every node under `n`, in key order, appended to `out`. */
function collect<V, T>(n: Node<V> | undefined, pick: (n: Node<V>) => T, out: T[]): T[] {
  const stack: Node<V>[] = [];
  let at = n;
  while (at !== undefined || stack.length > 0) {
    while (at !== undefined) {
      stack.push(at);
      at = at.left;
    }
    const top = stack.pop() as Node<V>;
    out.push(pick(top));
    at = top.right;
  }
  return out;
}

const pickEntry = <V>(n: Node<V>): [string, V] => [n.key, n.value];
const pickKey = <V>(n: Node<V>): string => n.key;
const pickValue = <V>(n: Node<V>): V => n.value;

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
    return lookup(this.#root, key)?.value;
  }

  has(key: string): boolean {
    return lookup(this.#root, key) !== undefined;
  }

  /** A map with `key` set to `value`; this one is unchanged. */
  set(key: string, value: V): PersistentMap<V> {
    const [root, added] = insert(this.#root, key, value);
    return new PersistentMap(root, added ? this.size + 1 : this.size);
  }

  /** The tree's height (tests: it stays logarithmic whatever the keys). */
  get height(): number {
    return heightOf(this.#root);
  }

  /**
   * Adds every tree node of this map to `seen` (tests: the structure the
   * retained states hold together, shared nodes counted once).
   */
  collectNodes(seen: Set<object>): void {
    collect(this.#root, (n) => seen.add(n).size, []);
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
