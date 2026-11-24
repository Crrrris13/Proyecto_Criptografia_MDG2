

#encriptado y desencriptado

from dataclasses import dataclass, field
from typing import List, Tuple

from rsa_math import es_primo, mcd, inverso_modular, exponenciacion_modular

N_MIN = 126126        
N_MAX = 1000000       
ASCII_MIN = 32
ASCII_MAX = 126
DIGITOS = "0123456789"


class ErrorRSA(ValueError):
    """Error de validación con un mensaje comprensible para el usuario."""


# -- resultados
@dataclass
class FilaCifrado:
    indice: int
    caracteres: str
    codigos: Tuple[int, int]
    m: int
    c: int


@dataclass
class ResultadoCifrado:
    p: int
    q: int
    e: int
    n: int
    phi: int
    L: int
    relleno: bool
    mensaje_relleno: str
    filas: List[FilaCifrado] = field(default_factory=list)
    cifrado: str = ""


@dataclass
class FilaDescifrado:
    indice: int
    c: int
    m: int
    codigos: Tuple[int, int]
    caracteres: str


@dataclass
class ResultadoDescifrado:
    p: int
    q: int
    e: int
    n: int
    phi: int
    d: int
    L: int
    relleno: bool
    texto_recuperado: str
    mensaje: str
    filas: List[FilaDescifrado] = field(default_factory=list)


# ------ validación
def parsear_entero(texto, nombre):
    s = texto.strip()
    if s == "":
        raise ErrorRSA(f"{nombre} está vacío. Ingresa un número entero.")
    cuerpo = s[1:] if s[0] in "+-" else s
    if cuerpo == "" or any(ch not in DIGITOS for ch in cuerpo):
        raise ErrorRSA(f"{nombre} debe ser un número entero (se recibió '{s}').")
    if len(cuerpo) > 18:
        raise ErrorRSA(f"{nombre} es demasiado grande (máximo 18 dígitos).")
    return int(s)


def validar_parametros(p, q, e):
    
    for nombre, v in (("p", p), ("q", q)):
        if v < 2:
            raise ErrorRSA(f"{nombre} = {v} no es primo (debe ser mayor o igual que 2).")
        if v >= N_MAX // 2:
            raise ErrorRSA(
                f"{nombre} = {v} es demasiado grande: n = p·q debe ser menor que "
                f"{N_MAX}, así que cada primo debe ser menor que {N_MAX // 2}."
            )
    if not es_primo(p):
        raise ErrorRSA(f"p = {p} no es primo.")
    if not es_primo(q):
        raise ErrorRSA(f"q = {q} no es primo.")
    if p == q:
        raise ErrorRSA("p y q deben ser primos distintos.")

    n = p * q
    phi = (p - 1) * (q - 1)
    if not (N_MIN < n < N_MAX):
        raise ErrorRSA(
            f"n = p·q = {n} está fuera del rango permitido: debe cumplirse "
            f"{N_MIN} < n < {N_MAX}."
        )
    if e <= 1:
        raise ErrorRSA(f"e = {e} no es válido: debe ser mayor que 1.")
    g = mcd(e, phi)
    if g != 1:
        raise ErrorRSA(f"e = {e} no es primo relativo con φ = {phi} (MCD = {g}).")
    return n, phi


def validar_mensaje(mensaje):
    if len(mensaje) == 0:
        raise ErrorRSA("El mensaje está vacío.")
    for pos, ch in enumerate(mensaje, start=1):
        codigo = ord(ch)
        if not (ASCII_MIN <= codigo <= ASCII_MAX):
            raise ErrorRSA(
                f"Carácter no admitido en la posición {pos}: {ch!r} "
                f"(código {codigo}). Solo se permiten códigos ASCII del "
                f"{ASCII_MIN} al {ASCII_MAX}."
            )


def validar_cifrado(texto, n):
    s = texto.strip()
    if s == "":
        raise ErrorRSA("El cifrado C está vacío.")
    bloques = []
    for i, parte in enumerate(s.split(" "), start=1):
        if parte == "":
            raise ErrorRSA(
                f"Bloque {i} vacío: separa los bloques con exactamente un espacio."
            )
        if len(parte) != 6 or any(ch not in DIGITOS for ch in parte):
            raise ErrorRSA(
                f"Bloque {i} mal formado ('{parte}'): cada bloque debe tener "
                "exactamente 6 dígitos decimales."
            )
        c = int(parte)
        if not (0 <= c < n):
            raise ErrorRSA(f"Bloque {i} ({parte}) fuera de rango: debe cumplirse 0 ≤ c < n = {n}.")
        bloques.append(c)
    return bloques


def validar_longitud(texto, k):
    s = texto.strip()
    if s == "" or any(ch not in DIGITOS for ch in s):
        raise ErrorRSA("L debe ser un entero positivo.")
    L = int(s)
    if L not in (2 * k, 2 * k - 1):
        raise ErrorRSA(
            f"L = {L} es inconsistente con {k} bloque(s): debe ser {2 * k} "
            f"(sin relleno) o {2 * k - 1} (con relleno)."
        )
    return L


# --- encriptar
def encriptar(mensaje, p, q, e):
    n, phi = validar_parametros(p, q, e)
    validar_mensaje(mensaje)

    L = len(mensaje)
    relleno = (L % 2 == 1)
    texto = mensaje + " " if relleno else mensaje

    filas = []
    for i in range(0, len(texto), 2):
        pareja = texto[i:i + 2]
        codigos = (ord(pareja[0]), ord(pareja[1]))
        m = int(f"{codigos[0]:03d}{codigos[1]:03d}")
        c = exponenciacion_modular(m, e, n)
        filas.append(FilaCifrado(i // 2 + 1, pareja, codigos, m, c))

    cifrado = " ".join(f"{f.c:06d}" for f in filas)
    return ResultadoCifrado(p, q, e, n, phi, L, relleno, texto, filas, cifrado)


# -- desencriptar
def desencriptar(cifrado, L_texto, p, q, e):
    n, phi = validar_parametros(p, q, e)
    bloques = validar_cifrado(cifrado, n)
    L = validar_longitud(L_texto, len(bloques))
    d = inverso_modular(e, phi)

    filas = []
    for i, c in enumerate(bloques, start=1):
        m = exponenciacion_modular(c, d, n)
        m6 = f"{m:06d}"
        a, b = int(m6[:3]), int(m6[3:])
        if not (ASCII_MIN <= a <= ASCII_MAX and ASCII_MIN <= b <= ASCII_MAX):
            raise ErrorRSA(
                f"El bloque {i} ({c:06d}) produjo m = {m6}, que no corresponde a "
                f"dos códigos ASCII entre {ASCII_MIN} y {ASCII_MAX}. "
                "Revisa p, q, e y C."
            )
        filas.append(FilaDescifrado(i, c, m, (a, b), chr(a) + chr(b)))

    texto = "".join(f.caracteres for f in filas)
    relleno = (L % 2 == 1)
    if relleno:
        if texto[-1] != " ":
            raise ErrorRSA(
                "L es impar, pero el último carácter recuperado no es un espacio "
                "de relleno. Revisa L y los demás datos."
            )
        mensaje = texto[:-1]  # se retira exactamente el relleno
    else:
        mensaje = texto
    return ResultadoDescifrado(p, q, e, n, phi, d, L, relleno, texto, mensaje, filas)
