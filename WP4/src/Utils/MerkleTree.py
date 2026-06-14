"""
Struttura dati Merkle Tree per la verifica delle schede.

Espone:
  build_merkle_tree      costruzione bottom-up
  generate_merkle_proof  prova di inclusione per una foglia
  verify_merkle_proof    verifica della prova rispetto alla root
"""

from Utils.crypto import hash_SHA256


def build_merkle_tree(leaves: list[bytes]) -> tuple[bytes, list[list[bytes]]]:
    """
    Costruisce il Merkle Tree a partire dall'elenco di foglie *leaves*.

    Ogni foglia deve essere già un digest SHA-256 (32 byte).
    Se il numero di nodi ad un livello è dispari, l'ultimo viene duplicato.

    Restituisce:
      root  – digest radice (bytes)
      tree  – lista di livelli, dal basso (foglie) verso l'alto (radice)
    """
    if not leaves:
        raise ValueError("La lista di foglie non può essere vuota")

    tree: list[list[bytes]] = [list(leaves)]

    while len(tree[-1]) > 1:
        level = tree[-1]
        if len(level) % 2 == 1:
            level = level + [level[-1]]   # duplica l'ultimo nodo se dispari
        tree.append([
            hash_SHA256(level[i] + level[i + 1])
            for i in range(0, len(level), 2)
        ])

    return tree[-1][0], tree


def generate_merkle_proof(
    leaf_index: int,
    tree: list[list[bytes]],
) -> list[tuple[str, bytes]]:
    """
    Genera la Merkle Proof per la foglia all'indice *leaf_index*.

    Restituisce una lista di coppie (posizione, hash_fratello) dove
    posizione ∈ {"left", "right"} indica da che lato si trova il fratello
    rispetto al nodo corrente. La lista va letta dal basso verso la radice.
    """
    proof: list[tuple[str, bytes]] = []
    idx = leaf_index

    for level in tree[:-1]:   # esclude la radice
        if len(level) % 2 == 1:
            level = level + [level[-1]]

        sibling_idx = idx ^ 1          # XOR con 1: flip del bit meno significativo
        position    = "right" if sibling_idx > idx else "left"
        proof.append((position, level[sibling_idx]))
        idx //= 2

    return proof


def verify_merkle_proof(
    leaf: bytes,
    proof: list[tuple[str, bytes]],
    root: bytes,
) -> bool:
    """
    Verifica che *leaf* sia inclusa nell'albero con radice *root*,
    usando la Merkle Proof *proof*.

    Restituisce True se la verifica ha esito positivo, False altrimenti.
    """
    current = leaf

    for position, sibling in proof:
        if position == "right":
            current = hash_SHA256(current + sibling)
        else:
            current = hash_SHA256(sibling + current)

    return current == root