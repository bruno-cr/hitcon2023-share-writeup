"""
Demonstracao local (sem Docker, sem rede) do ataque ao desafio Share.
Reimplementa o SecretSharing exatamente como no server.py original
(incluindo o bug), simula o servidor como uma FUNCAO local, e reproduz
o ataque completo: forca bruta de a0 mod p usando a testemunha (p-1)
+ CRT para juntar varios modulos.

Uso: python3 demo_share_attack.py
"""

import random
import time
from math import gcd

# -----------------------------------------------------------------
# 1) Reimplementacao FIEL do server.py original (mesmo bug)
# -----------------------------------------------------------------

def get_random_range(a, b):
    """Equivalente a Crypto.Util.number.getRandomRange(a, b): retorna
    um inteiro em [a, b-1]. """
    return random.randrange(a, b)


class SecretSharing:
    def __init__(self, p, n, secret):
        self.p = p
        self.n = n
        # BUG ORIGINAL: deveria ser getRandomRange(0, self.p)
        # mas usa (0, self.p - 1) -> nunca sorteia o valor (p-1)
        self.poly = [secret] + [get_random_range(0, self.p - 1) for _ in range(n - 1)]

    def evaluate(self, x):
        return sum(
            self.poly[i] * pow(x, i, self.p) for i in range(len(self.poly))
        ) % self.p

    def get_shares(self):
        return [self.evaluate(i + 1) for i in range(self.n)]


# -----------------------------------------------------------------
# 2) "Servidor" local: em vez de socket, uma funcao Python.
#    Isso satisfaz "conteiner unico ou funcao local" do escopo.
# -----------------------------------------------------------------

def servidor_local(secret, p, n):
    """Simula a interacao com o servidor: dado p e n escolhidos pelo
    atacante, devolve os primeiros n-1 shares (igual ao server.py
    original, que faz `shares[:-1]`)."""
    shares_completos = SecretSharing(p, n, secret).get_shares()
    return shares_completos[:-1]


# -----------------------------------------------------------------
# 3) Interpolacao de Lagrange COMPLETA (todos os coeficientes,
#    nao so f(0)) -- e o que precisamos pra achar a "testemunha" p-1
# -----------------------------------------------------------------

def poly_mul(a, b, p):
    """Multiplica dois polinomios (listas de coeficientes, do termo
    independente para o de maior grau), mod p."""
    resultado = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            resultado[i + j] = (resultado[i + j] + ai * bj) % p
    return resultado


def lagrange_interpola_completo(pontos, p):
    """Dado uma lista de (x_i, y_i), devolve TODOS os coeficientes
    do polinomio interpolador (grau len(pontos)-1), mod p."""
    n = len(pontos)
    resultado = [0] * n
    for i in range(n):
        x_i, y_i = pontos[i]
        numerador = [1]  # polinomio constante 1, vai virando o produto (x - x_j)
        denominador = 1
        for j in range(n):
            if j == i:
                continue
            x_j, _ = pontos[j]
            numerador = poly_mul(numerador, [(-x_j) % p, 1], p)
            denominador = (denominador * (x_i - x_j)) % p
        inv_denominador = pow(denominador, -1, p)
        peso = (y_i * inv_denominador) % p
        termo = [(c * peso) % p for c in numerador]
        for k in range(len(termo)):
            resultado[k] = (resultado[k] + termo[k]) % p
    return resultado


# -----------------------------------------------------------------
# 4) O ataque: descobrir secret mod p usando a testemunha (p-1)
# -----------------------------------------------------------------

def recupera_secret_mod_p(secret_real, p, n=14, max_consultas=200):
    """Forca bruta de a0 (candidato a `secret mod p`), eliminando
    candidatos que produzem algum coeficiente igual a p-1 -- valor
    que a implementacao com bug NUNCA poderia gerar."""
    candidatos = set(range(p))
    consultas = 0

    while len(candidatos) > 1 and consultas < max_consultas:
        shares = servidor_local(secret_real, p, n)  # consulta o "servidor"
        consultas += 1

        for a0 in list(candidatos):
            pontos = [(0, a0)] + [(i + 1, shares[i]) for i in range(n - 1)]
            poly = lagrange_interpola_completo(pontos, p)
            # se QUALQUER coeficiente (exceto a0) for p-1, esse a0 e impossivel
            if (p - 1) in poly[1:]:
                candidatos.discard(a0)

    assert len(candidatos) == 1, f"Nao convergiu para 1 candidato (sobraram {len(candidatos)}) apos {consultas} consultas"
    return candidatos.pop(), consultas


# -----------------------------------------------------------------
# 5) CRT: juntar varios "secret mod p_i" num unico valor
# -----------------------------------------------------------------

def crt(restos, modulos):
    M = 1
    for m in modulos:
        M *= m
    X = 0
    for r_i, m_i in zip(restos, modulos):
        M_i = M // m_i
        inv = pow(M_i, -1, m_i)
        X += r_i * M_i * inv
    return X % M


# -----------------------------------------------------------------
# 6) Demonstracao de ponta a ponta
# -----------------------------------------------------------------

if __name__ == "__main__":
    inicio = time.time()

    random.seed(1337)  # reprodutibilidade da demo

    # Em uma demo local, usamos um "secret" pequeno para o ataque
    # rodar em segundos. No desafio real, o secret e um inteiro de
    # 256 bits (32 bytes aleatorios) -- o metodo e IDENTICO, so
    # precisa de mais primos ate o produto passar de 2**256.
    secret_real = 123456789

    # Primos escolhidos pelo atacante (precisam ser > 13, por causa
    # da checagem `13 < n < p` no servidor original, com n=14 fixo)
    primos = [17, 19, 23, 29, 31, 37, 41]

    produto = 1
    for p in primos:
        produto *= p
    assert produto > secret_real, "Produto dos primos precisa ultrapassar o segredo"

    print(f"Segredo real (para conferencia): {secret_real}")
    print(f"Primos escolhidos: {primos}")
    print(f"Produto dos primos: {produto}\n")

    restos = []
    for p in primos:
        r, n_consultas = recupera_secret_mod_p(secret_real, p, n=14)
        esperado = secret_real % p
        status = "OK" if r == esperado else "ERRO"
        print(f"  p={p:3d} -> secret mod p = {r:3d} (esperado {esperado:3d}) "
              f"[{status}] ({n_consultas} consulta(s))")
        restos.append(r)

    segredo_reconstruido = crt(restos, primos)
    print(f"\nSegredo reconstruido via CRT: {segredo_reconstruido}")
    print(f"Segredo real:                 {secret_real}")
    assert segredo_reconstruido == secret_real, "FALHA: segredo nao bateu!"
    print("\n[SUCESSO] O ataque recuperou o segredo completo, ponta a ponta.")

    tempo_total = time.time() - inicio
    print(f"tempo total: {round(tempo_total, 2)} s")
