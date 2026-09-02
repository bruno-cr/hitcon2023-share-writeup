"""
Extensao do demo_share_attack.py: aceita uma senha/frase em TEXTO como
"secret", converte automaticamente para inteiro (do mesmo jeito que o
servidor original faz com os.urandom -> bytes_to_long), e calcula
SOZINHA quantos primos de uma lista pre-gerada sao necessarios ate o
produto ultrapassar o segredo.

Nao pensado para rodar ao vivo em apresentacao (tempo variavel
dependendo do tamanho da senha) -- e material de apoio/evidencia
adicional, para mostrar automacao sobre a demo principal.

Uso: python3 demo_share_attack_texto.py "minha frase secreta aqui"
"""

import random
import sys
import time

# Reaproveita as pecas ja validadas do script principal
from demo_share_attack import (
    servidor_local,
    recupera_secret_mod_p,
    crt,
)


def texto_para_inteiro(texto: str) -> int:
    """Equivalente a bytes_to_long(texto.encode()) -- sem depender de
    pycryptodome, para manter a dependencia minima (Python puro,
    zero bibliotecas externas)."""
    dados = texto.encode("utf-8")
    return int.from_bytes(dados, byteorder="big")


def eh_primo(numero: int, rodadas: int = 20) -> bool:
    """Teste de primalidade de Miller-Rabin (probabilistico, mas com
    taxa de erro desprezivel para 20 rodadas). Evita depender do
    sympy so para testar primalidade."""
    if numero < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if numero % p == 0:
            return numero == p

    # escreve numero-1 como d * 2^s
    d = numero - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rodadas):
        a = random.randrange(2, numero - 1)
        x = pow(a, d, numero)
        if x == 1 or x == numero - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, numero)
            if x == numero - 1:
                break
        else:
            return False
    return True


def proximo_primo(a_partir_de: int) -> int:
    """Menor primo estritamente maior que `a_partir_de`."""
    candidato = a_partir_de + 1
    if candidato <= 2:
        return 2
    if candidato % 2 == 0:
        candidato += 1
    while not eh_primo(candidato):
        candidato += 2
    return candidato


def gera_primos_suficientes(valor_alvo: int, primo_minimo: int = 14) -> list:
    """Gera primos crescentes (todos > primo_minimo, por causa do
    `13 < n < p` do servidor original) ate o produto ultrapassar
    valor_alvo. Devolve a lista de primos usados."""
    primos = []
    produto = 1
    candidato = primo_minimo
    while produto <= valor_alvo:
        candidato = proximo_primo(candidato)
        primos.append(candidato)
        produto *= candidato
    return primos


def ataca_segredo_texto(texto: str, n: int = 14, seed: int = 1337):
    random.seed(seed)

    secret_real = texto_para_inteiro(texto)
    tamanho_bits = secret_real.bit_length()

    print(f"Texto de entrada: {texto!r}")
    print(f"Convertido para inteiro: {secret_real}")
    print(f"Tamanho em bits: {tamanho_bits}\n")

    primos = gera_primos_suficientes(secret_real)
    produto = 1
    for p in primos:
        produto *= p

    print(f"Primos necessarios ({len(primos)} no total): {primos}")
    print(f"Produto dos primos: {produto}")
    print(f"Produto > segredo? {produto > secret_real}\n")

    inicio = time.time()
    restos = []
    for p in primos:
        r, n_consultas = recupera_secret_mod_p(secret_real, p, n=n)
        esperado = secret_real % p
        status = "OK" if r == esperado else "ERRO"
        print(f"  p={p:6d} -> secret mod p = {r:6d} (esperado {esperado:6d}) "
              f"[{status}] ({n_consultas} consulta(s))")
        restos.append(r)

    segredo_reconstruido = crt(restos, primos)
    tempo_total = time.time() - inicio

    print(f"\nSegredo reconstruido via CRT: {segredo_reconstruido}")
    print(f"Segredo real:                 {secret_real}")
    assert segredo_reconstruido == secret_real, "FALHA: segredo nao bateu!"

    texto_recuperado = segredo_reconstruido.to_bytes(
        (segredo_reconstruido.bit_length() + 7) // 8, byteorder="big"
    ).decode("utf-8")
    print(f"Texto recuperado: {texto_recuperado!r}")

    print(f"\n[SUCESSO] Segredo em texto recuperado corretamente.")
    print(f"tempo total: {round(tempo_total, 2)} s")


if __name__ == "__main__":
    frase = sys.argv[1] if len(sys.argv) > 1 else "senha de teste 2026"
    ataca_segredo_texto(frase)
