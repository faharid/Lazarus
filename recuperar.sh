#!/usr/bin/env bash
# recuperar.sh - Recupera el secreto escondido en la imagen.
#
# Uso:  ./recuperar.sh <imagen.jpg> [hash_esperado]
#
# Te va a pedir:
#   - La clave A (la de la imagen; esta en el documento de instrucciones).
#   - Dos fragmentos cualesquiera de los tres: el numero y las 12 palabras.
#
# Requisitos: outguess, ssss, gnupg, python3 (Ubuntu: sudo apt install outguess ssss gnupg python3)

set -euo pipefail
umask 077

if [[ $# -lt 1 ]]; then
  echo "Uso: $0 <imagen.jpg> [hash_esperado]" >&2
  exit 1
fi
IMG="$1"
HASH_ESPERADO="${2:-}"

DIR="$(cd "$(dirname "$0")" && pwd)"
PAL="$DIR/palabras.py"
for bin in outguess ssss-combine gpg sha256sum python3; do
  command -v "$bin" >/dev/null || { echo "Falta el programa: $bin  (sudo apt install outguess ssss gnupg python3)" >&2; exit 1; }
done
[[ -f "$IMG" ]] || { echo "No encuentro la imagen: $IMG" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; unset CLAVE_A CLAVE_B F1 F2' EXIT
export GNUPGHOME="$TMP/gnupg"; mkdir -m 700 "$GNUPGHOME"

# --- 1. Comprobar que la imagen es la original -------------------------------
HASH="$(sha256sum "$IMG" | cut -d' ' -f1)"
echo "Huella (SHA-256) de la imagen: $HASH"
if [[ -n "$HASH_ESPERADO" ]]; then
  if [[ "${HASH,,}" == "${HASH_ESPERADO,,}" ]]; then
    echo "OK: la imagen es la original."
  else
    echo "ATENCION: la huella NO coincide. Esta imagen fue modificada o no es la correcta."
    echo "Busca otra copia (USB o los otros respaldos) antes de seguir."
    exit 1
  fi
fi
echo

# --- 2. Extraer de la imagen con la clave A ---------------------------------
if [[ -z "${CLAVE_A:-}" ]]; then
  read -r -s -p "Clave A (la de la imagen): " CLAVE_A; echo
fi
{ ( outguess -k "$CLAVE_A" -r "$IMG" "$TMP/secreto.gpg" ) >/dev/null 2>&1; } 2>/dev/null || true
# Un archivo cifrado por GPG con clave simetrica empieza con 8c 0d (formato clasico) o c3 (formato nuevo)
CABECERA="$( [[ -s "$TMP/secreto.gpg" ]] && od -An -tx1 -N2 "$TMP/secreto.gpg" | tr -d ' \n' || true)"
if [[ "$CABECERA" != "8c0d" && "${CABECERA:0:2}" != "c3" ]]; then
  echo "No se pudo extraer nada valido. Revisa la clave A (mayusculas, espacios)"
  echo "o prueba con otra copia de la imagen (puede estar dañada)."
  exit 1
fi
echo "Contenido extraido de la imagen."
echo

# --- 3. Reconstruir la clave B con dos fragmentos ------------------------------
leer_fragmento() {  # $1 = etiqueta, $2 = valor ya dado (pruebas)
  local linea="$2" hx
  while true; do
    [[ -n "$linea" ]] || read -r -p "$1 (numero y 12 palabras): " linea
    if hx="$(python3 "$PAL" a-hex "$linea" 2>"$TMP/err")"; then
      echo "$hx"; return 0
    fi
    echo "  $(cat "$TMP/err")" >&2
    [[ -z "$2" ]] || return 1
    linea=""
  done
}
echo "Escribe dos fragmentos. Ejemplo:  2 pulpo mismo nieve ... (12 palabras)"
H1="$(leer_fragmento "Fragmento A" "${F1:-}")" || exit 1
H2="$(leer_fragmento "Fragmento B" "${F2:-}")" || exit 1
if [[ "${H1%%-*}" == "${H2%%-*}" ]]; then
  echo "Escribiste dos veces el fragmento ${H1%%-*}. Necesitas dos fragmentos distintos."
  exit 1
fi
CLAVE_B="$(printf '%s\n%s\n' "$H1" "$H2" | ssss-combine -t 2 -x -q 2>&1 >/dev/null | tr -d '\n' || true)"
if [[ ! "$CLAVE_B" =~ ^[0-9a-f]{32}$ ]]; then
  echo "Los fragmentos no se pudieron combinar. Revisa que sean de la misma version del kit."
  exit 1
fi

# --- 4. Descifrar --------------------------------------------------------------
if ! gpg --batch --quiet --pinentry-mode loopback --passphrase-fd 3 \
       -d "$TMP/secreto.gpg" 3<<<"$CLAVE_B" >"$TMP/secreto.txt" 2>/dev/null; then
  echo "No se pudo descifrar. Los fragmentos no corresponden a esta imagen (puede ser una version vieja)."
  exit 1
fi

echo
echo "================= CONTENIDO ================="
cat "$TMP/secreto.txt"
echo "============================================="
echo
echo "Esto no se guardo en ningun archivo. Anota lo que necesites y cierra esta ventana."
