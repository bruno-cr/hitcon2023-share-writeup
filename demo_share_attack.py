"""
Demonstracao local (sem Docker, sem rede) do ataque ao desafio Share.
Reimplementa o SecretSharing exatamente como no server.py original
(incluindo o bug), simula o servidor como uma FUNCAO local, e reproduz
o ataque completo: forca bruta de a0 mod p usando a testemunha (p-1)
+ CRT para juntar varios modulos.

Uso:
  python3 demo_share_attack.py                # usa o secret de demonstracao (123456789)
  python3 demo_share_attack.py 987654321       # usa o secret inteiro informado
"""

import random
import sys
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

def recupera_secret_mod_p(secret_real, p, n=14, max_consultas=200, verboso=False):
    """Forca bruta de a0 (candidato a `secret mod p`), eliminando
    candidatos que produzem algum coeficiente igual a p-1 -- valor
    que a implementacao com bug NUNCA poderia gerar.

    Se verboso=True, imprime uma tabela mostrando, rodada a rodada,
    quantos candidatos foram eliminados e quantos restam -- util para
    apresentacao com primos pequenos (a tabela fica ilegivel se p for
    grande, entao so ative verboso para p pequeno)."""
    candidatos = set(range(p))
    consultas = 0

    if verboso:
        print(f"    Inicio: {len(candidatos)} candidatos possiveis -> {sorted(candidatos)}")

    while len(candidatos) > 1 and consultas < max_consultas:
        shares = servidor_local(secret_real, p, n)  # consulta o "servidor"
        consultas += 1
        antes = set(candidatos)

        for a0 in list(candidatos):
            pontos = [(0, a0)] + [(i + 1, shares[i]) for i in range(n - 1)]
            poly = lagrange_interpola_completo(pontos, p)
            # se QUALQUER coeficiente (exceto a0) for p-1, esse a0 e impossivel
            if (p - 1) in poly[1:]:
                candidatos.discard(a0)

        if verboso:
            eliminados = sorted(antes - candidatos)
            print(f"    Rodada {consultas}: eliminou {len(eliminados)} candidato(s) "
                  f"{eliminados} | sobraram {len(candidatos)} -> {sorted(candidatos)}")

    assert len(candidatos) == 1, f"Nao convergiu para 1 candidato (sobraram {len(candidatos)}) apos {consultas} consultas"
    return candidatos.pop(), consultas


# -----------------------------------------------------------------
# 5) CRT: juntar varios "secret mod p_i" num unico valor
# -----------------------------------------------------------------

def crt(restos, modulos, verboso=False):
    M = 1
    for m in modulos:
        M *= m

    if verboso:
        print(f"    M (produto de todos os primos): {M}")

    X = 0
    for r_i, m_i in zip(restos, modulos):
        M_i = M // m_i
        inv = pow(M_i, -1, m_i)
        contribuicao = (r_i * M_i * inv) % M
        X += r_i * M_i * inv

        if verboso:
            print(f"    p={m_i:3d}: resto={r_i:3d} | M_i=M/{m_i}={M_i} | "
                  f"inverso de M_i mod {m_i} = {inv} | contribuicao = {contribuicao}")

    resultado = X % M
    if verboso:
        print(f"    soma de todas as contribuicoes, mod M: {resultado}")

    return resultado


# -----------------------------------------------------------------
# 5b) Geracao automatica de primos suficientes (para secrets maiores
#     que o de demonstracao, passados via linha de comando)
# -----------------------------------------------------------------

def eh_primo(numero, rodadas=20):
    """Teste de primalidade de Miller-Rabin (Python puro, sem libs)."""
    if numero < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if numero % p == 0:
            return numero == p
    d = numero - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rodadas):
        a = random.randrange(2, numero - 1)
        x = pow(a, d, numero)
        if x in (1, numero - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, numero)
            if x == numero - 1:
                break
        else:
            return False
    return True


def proximo_primo(a_partir_de):
    candidato = a_partir_de + 1
    if candidato <= 2:
        return 2
    if candidato % 2 == 0:
        candidato += 1
    while not eh_primo(candidato):
        candidato += 2
    return candidato


def gera_primos_suficientes(valor_alvo, primo_minimo=14):
    """Gera primos crescentes (> primo_minimo, por causa do
    `int(13.37) < n < p` do servidor original) ate o produto
    ultrapassar valor_alvo."""
    primos = []
    produto = 1
    candidato = primo_minimo
    while produto <= valor_alvo:
        candidato = proximo_primo(candidato)
        primos.append(candidato)
        produto *= candidato
    return primos


# -----------------------------------------------------------------
# 6) Demonstracao de ponta a ponta
# -----------------------------------------------------------------

if __name__ == "__main__":
    inicio = time.time()

    random.seed(1337)  # reprodutibilidade da demo

    # Lista fixa de primos pequenos, usada com o secret de demonstracao
    # (rapida, ~0.3s). Se um secret diferente for passado por linha de
    # comando, os primos sao gerados automaticamente ate o produto
    # ultrapassar esse novo valor (pode demorar mais).
    PRIMOS_PADRAO = [17, 19, 23, 29, 31, 37, 41]
    SECRET_PADRAO = 123456789

    if len(sys.argv) > 1:
        secret_real = int(sys.argv[1])
        produto_padrao = 1
        for p in PRIMOS_PADRAO:
            produto_padrao *= p
        if secret_real < produto_padrao:
            # o secret informado ainda cabe na lista padrao de primos
            primos = PRIMOS_PADRAO
        else:
            # secret maior -> gera primos novos, o suficiente para cobrir
            primos = gera_primos_suficientes(secret_real)
    else:
        secret_real = SECRET_PADRAO
        primos = PRIMOS_PADRAO

    produto = 1
    for p in primos:
        produto *= p
    assert produto > secret_real, "Produto dos primos precisa ultrapassar o segredo"

    print(f"Segredo real (para conferencia): {secret_real}")
    print(f"Primos escolhidos ({len(primos)}): {primos}")
    print(f"Produto dos primos: {produto}\n")

    restos = []
    LIMITE_VERBOSO = 50  # so imprime a tabela rodada-a-rodada se p <= esse valor
    for p in primos:
        print(f"  p={p}:")
        r, n_consultas = recupera_secret_mod_p(
            secret_real, p, n=14, verboso=(p <= LIMITE_VERBOSO)
        )
        esperado = secret_real % p
        status = "OK" if r == esperado else "ERRO"
        print(f"    -> secret mod p = {r:3d} (esperado {esperado:3d}) "
              f"[{status}] ({n_consultas} consulta(s))\n")
        restos.append(r)

    print("Reconstruindo o segredo via CRT:")
    segredo_reconstruido = crt(restos, primos, verboso=(len(primos) <= LIMITE_VERBOSO))
    print(f"\nSegredo reconstruido via CRT: {segredo_reconstruido}")
    print(f"Segredo real:                 {secret_real}")
    assert segredo_reconstruido == secret_real, "FALHA: segredo nao bateu!"
    print("\n[SUCESSO] O ataque recuperou o segredo completo, ponta a ponta.")

    tempo_total = time.time() - inicio
    print(f"tempo total: {round(tempo_total, 2)} s")
