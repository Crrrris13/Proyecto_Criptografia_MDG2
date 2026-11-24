#funciones de mate discreta


def es_primo(n):

    if n < 2:
        return False
    if n < 4:  
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def mcd(a: int, b: int) -> int:
    
    residuo= a % b

    if residuo!=0:
      return mcd(b,residuo)

    else:
      return b


def inverso_modular(a: int, m: int) -> int:
    
    r0, r1 = m, a % m
    t0, t1 = 0, 1
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if r0 != 1:
        raise ValueError("No existe inverso modular: MCD(a, m) != 1")
    
    return t0 % m


def exponenciacion_modular(b: int, e: int, n: int) -> int:
    
    if e == 0:
        return 1

    mitad = exponenciacion_modular(b, e // 2, n)
    resultado = (mitad * mitad) % n

    if e % 2 != 0:
        resultado = (resultado * b) % n

    return resultado


