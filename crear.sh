#!/usr/bin/env bash
# crear.sh - Genera el kit de acceso de emergencia.
#
# Uso:  ./crear.sh <imagen_base.jpg> <secreto.txt> <carpeta_salida>
#
# Que hace:
#   1. Genera una clave B aleatoria de 128 bits (nadie la elige, nadie la memoriza).
#   2. Cifra secreto.txt con GPG (AES-256) usando la clave B.
#   3. Esconde el cifrado dentro de la imagen con OutGuess usando la clave A (te la pide).
#   4. Parte la clave B en 3 fragmentos Shamir de 12 palabras; con 2 cualesquiera se reconstruye.
#   5. Verifica que todo se recupere bien antes de terminar.
#   6. Olvida la clave B completa. Solo quedan los fragmentos.
#
# Requisitos: outguess, ssss, gnupg, python3 (Ubuntu: sudo apt install outguess ssss gnupg python3)

set -euo pipefail
umask 077

if [[ $# -ne 3 ]]; then
  echo "Uso: $0 <imagen_base.jpg> <secreto.txt> <carpeta_salida>" >&2
  exit 1
fi

IMG_IN="$1"
SECRETO="$2"
OUT="$3"

DIR="$(cd "$(dirname "$0")" && pwd)"
PAL="$DIR/palabras.py"
[[ -f "$PAL" && -f "$DIR/palabras-es.txt" ]] || { echo "Faltan palabras.py o palabras-es.txt junto al script" >&2; exit 1; }
for bin in outguess ssss-split ssss-combine gpg sha256sum od python3; do
  command -v "$bin" >/dev/null || { echo "Falta: $bin" >&2; exit 1; }
done
[[ -f "$IMG_IN" ]]  || { echo "No existe la imagen: $IMG_IN" >&2; exit 1; }
[[ -f "$SECRETO" ]] || { echo "No existe el secreto: $SECRETO" >&2; exit 1; }
case "${IMG_IN,,}" in *.jpg|*.jpeg) ;; *) echo "La imagen debe ser JPEG" >&2; exit 1;; esac

mkdir -p "$OUT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; unset CLAVE_A CLAVE_B' EXIT
export GNUPGHOME="$TMP/gnupg"; mkdir -m 700 "$GNUPGHOME"

# --- Clave A (para la imagen) ---------------------------------------------
if [[ -n "${CLAVE_A:-}" ]]; then
  : # ya viene por variable de entorno (solo para pruebas)
else
  read -r -s -p "Clave A (la de la imagen): " CLAVE_A; echo
  read -r -s -p "Repite la clave A: " CLAVE_A2; echo
  [[ "$CLAVE_A" == "$CLAVE_A2" ]] || { echo "Las claves A no coinciden" >&2; exit 1; }
  unset CLAVE_A2
fi
[[ ${#CLAVE_A} -ge 8 ]] || { echo "La clave A debe tener al menos 8 caracteres" >&2; exit 1; }

# --- Clave B (128 bits aleatorios) y sus 3 fragmentos en palabras ----------
# Se vuelve a sortear hasta que ningun fragmento tenga palabras de palabras-evitar.txt
for intento in $(seq 1 500); do
  CLAVE_B="$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
  ssss-split -t 2 -n 3 -x -s 128 -q <<<"$CLAVE_B" >"$TMP/frags.txt" 2>/dev/null
  mapfile -t FRAGS_HEX <"$TMP/frags.txt"
  [[ ${#FRAGS_HEX[@]} -eq 3 ]] || { echo "ssss no genero 3 fragmentos" >&2; exit 1; }
  FRAGS=(); LIMPIO=1
  for h in "${FRAGS_HEX[@]}"; do
    w="$(python3 "$PAL" a-palabras "$h")"
    [[ "$(python3 "$PAL" a-hex "$w")" == "$h" ]] || { echo "ERROR en la conversion a palabras" >&2; exit 1; }
    python3 "$PAL" limpio "$w" || LIMPIO=0
    FRAGS+=("$w")
  done
  [[ $LIMPIO -eq 1 ]] && break
done
[[ $LIMPIO -eq 1 ]] || { echo "No se logro evitar las palabras de la lista. Quita algunas de palabras-evitar.txt" >&2; exit 1; }

# --- Cifrar el secreto con la clave B --------------------------------------
gpg --batch --yes --quiet --pinentry-mode loopback --passphrase-fd 3 \
    --symmetric --cipher-algo AES256 --s2k-digest-algo SHA512 \
    --s2k-count 65011712 --compress-algo none \
    -o "$TMP/secreto.gpg" "$SECRETO" 3<<<"$CLAVE_B"

# --- Esconder en la imagen con la clave A ----------------------------------
IMG_OUT="$OUT/imagen.jpg"
if ! outguess -k "$CLAVE_A" -d "$TMP/secreto.gpg" "$IMG_IN" "$IMG_OUT" >"$TMP/og.log" 2>&1; then
  cat "$TMP/og.log" >&2
  echo "OutGuess fallo. Si dice que no cabe, usa una imagen mas grande o un secreto mas corto." >&2
  exit 1
fi

# --- Verificacion completa antes de entregar -------------------------------
{ ( outguess -k "$CLAVE_A" -r "$IMG_OUT" "$TMP/check.gpg" ) >/dev/null 2>&1; } 2>/dev/null || true
for par in "0 1" "0 2" "1 2"; do
  set -- $par
  B2="$(printf '%s\n%s\n' "$(python3 "$PAL" a-hex "${FRAGS[$1]}")" "$(python3 "$PAL" a-hex "${FRAGS[$2]}")" \
        | ssss-combine -t 2 -x -q 2>&1 >/dev/null | tr -d '\n')"
  [[ "$B2" == "$CLAVE_B" ]] || { echo "ERROR: los fragmentos $(( $1+1 )) y $(( $2+1 )) no reconstruyen la clave" >&2; exit 1; }
done
gpg --batch --quiet --pinentry-mode loopback --passphrase-fd 3 \
    -d "$TMP/check.gpg" 3<<<"$CLAVE_B" >"$TMP/check.txt" 2>/dev/null
cmp -s "$TMP/check.txt" "$SECRETO" || { echo "ERROR: lo recuperado no coincide con el secreto" >&2; exit 1; }

# --- Escribir salidas --------------------------------------------------------
FECHA="$(date +%Y-%m-%d)"
HASH="$(sha256sum "$IMG_OUT" | cut -d' ' -f1)"
for i in 0 1 2; do
  n=$((i+1))
  read -r -a W <<<"$(sed 's/ · / /g' <<<"${FRAGS[$i]}")"
  {
    echo "FRAGMENTO ${W[0]} DE 3  (se necesitan 2 cualesquiera)   Creado: $FECHA"
    echo
    echo "  ${FRAGS[$i]}"
    echo
    python3 "$PAL" tabla "${FRAGS[$i]}"
    echo
    echo "Escribe el numero ${W[0]} y las 12 palabras en orden. Tildes y mayusculas no importan."
    echo "Este fragmento solo no sirve para nada. No lo fotografies ni lo envies por chat."
  } >"$OUT/fragmento-$n.txt"
done
printf '%s  imagen.jpg\nCreado: %s\n' "$HASH" "$FECHA" >"$OUT/hash.txt"

echo
echo "Listo. Verificado: las 3 combinaciones de 2 fragmentos recuperan el secreto."
echo "  $OUT/imagen.jpg          -> subir al sitio TAL CUAL (sin optimizar) y guardar copias"
echo "  $OUT/fragmento-1..3.txt  -> imprimir, entregar, y BORRAR los archivos"
echo "  $OUT/hash.txt            -> va en el documento de instrucciones"
echo "  SHA-256: $HASH"
echo
echo "La clave B completa no se guardo en ningun lado."
echo "Recuerda borrar $SECRETO cuando termines."
