#!/usr/bin/env python3
"""Convierte fragmentos Shamir (hex de 128 bits) a 12 palabras y de vuelta.

Usa la lista BIP39 en español (la de las wallets cripto) con su checksum:
si una palabra está mal escrita, se detecta.

  palabras.py a-palabras 2-5f845837bc85cf8a3a0655316c792ebb
      -> "2 · palabra1 · ... · palabra12"
  palabras.py a-hex "2 pulpo mismo nieve ..."
      -> "2-5f84...."   (error con mensaje claro si algo está mal)

Al leer: no importan tildes, mayúsculas ni separadores; bastan las 4 primeras letras.
"""
import hashlib, os, re, sys, unicodedata

LISTA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "palabras-es.txt")
PALABRAS = [unicodedata.normalize("NFC", l.strip()) for l in open(LISTA, encoding="utf-8") if l.strip()]
assert len(PALABRAS) == 2048, "La lista de palabras está incompleta"


def norm(s):
    s = unicodedata.normalize("NFKD", s.lower())
    return "".join(c for c in s if not unicodedata.combining(c))


POR_PREFIJO = {norm(p)[:4]: i for i, p in enumerate(PALABRAS)}


def a_palabras(frag):
    idx, hx = frag.strip().split("-")[-2:]
    datos = bytes.fromhex(hx)
    assert len(datos) == 16, "Se esperaban 128 bits"
    cs = hashlib.sha256(datos).digest()[0] >> 4          # 4 bits de checksum
    n = (int.from_bytes(datos, "big") << 4) | cs           # 132 bits = 12 x 11
    ws = [PALABRAS[(n >> (11 * (11 - i))) & 0x7FF] for i in range(12)]
    return f"{idx} · " + " · ".join(ws)


def a_hex(linea):
    toks = [t for t in re.split(r"[\s·.,;:\-]+", linea.strip()) if t]
    if not toks or not toks[0].isdigit():
        raise ValueError("El fragmento debe empezar con su número (1, 2 o 3).")
    idx, ws = toks[0], toks[1:]
    if len(ws) != 12:
        raise ValueError(f"Hay {len(ws)} palabras y deben ser 12.")
    n = 0
    for pos, w in enumerate(ws, 1):
        k = norm(w)[:4]
        if k not in POR_PREFIJO:
            raise ValueError(f"La palabra {pos} ('{w}') no existe en la lista. Revísala.")
        n = (n << 11) | POR_PREFIJO[k]
    datos, cs = (n >> 4).to_bytes(16, "big"), n & 0xF
    if hashlib.sha256(datos).digest()[0] >> 4 != cs:
        raise ValueError("Las 12 palabras existen pero alguna está mal o fuera de orden.")
    return f"{idx}-{datos.hex()}"


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "limpio":
        # sale 0 si el fragmento no tiene palabras de palabras-evitar.txt
        ev = os.path.join(os.path.dirname(os.path.abspath(__file__)), "palabras-evitar.txt")
        malas = set()
        if os.path.exists(ev):
            malas = {norm(l.strip()) for l in open(ev, encoding="utf-8") if l.strip() and not l.startswith("#")}
        ws = {norm(w) for w in sys.argv[2].split(" · ")[1:]}
        sys.exit(1 if ws & malas else 0)
    if len(sys.argv) == 3 and sys.argv[1] == "tabla":
        ws = [w for w in sys.argv[2].split(" · ")][1:]
        for f in (0, 4, 8):
            print("   " + "".join(f"{f+i+1:>2}. {ws[f+i]:<12}" for i in range(4)).rstrip())
        sys.exit(0)
    if len(sys.argv) != 3 or sys.argv[1] not in ("a-palabras", "a-hex"):
        print(__doc__, file=sys.stderr); sys.exit(2)
    try:
        print(a_palabras(sys.argv[2]) if sys.argv[1] == "a-palabras" else a_hex(sys.argv[2]))
    except (ValueError, AssertionError) as e:
        print(e, file=sys.stderr); sys.exit(1)
