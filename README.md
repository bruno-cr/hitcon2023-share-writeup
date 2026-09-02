# HITCON CTF 2023 — Share (Crypto)

Write-up e reprodução do desafio **Share**, categoria Cripto do
HITCON CTF 2023, desenvolvido como avaliação (E1) da disciplina
**Segurança Cibernética (CCO-04.2.01)** — PPGCC, UFSCar.

## Membros do grupo

- Bruno Camargo Ribeiro
- Bruno Hiroki Nagao Anhaia
- Cilene Renata Real
- Emerson Hermann Lira dos Santos
- Gabriel Alves Moreira
- Jonathan Choy Rivera
- Thayná Marostica Machado da Silva

---

## 1. Identificação do desafio e objetivo

O desafio implementa **Shamir Secret Sharing (SSS)**: um servidor
sorteia um segredo de 32 bytes (256 bits) e permite ao cliente
solicitar "pedaços" (*shares*) desse segredo, escolhendo dois
parâmetros — um primo `p` e uma quantidade `n` de pedaços
(`13 < n < p`). O servidor gera um polinômio aleatório de grau
`n-1`, com o segredo como termo independente, e devolve `n-1` pontos
desse polinômio.

**Promessa de segurança do desafio:** com `n-1` pontos de um
polinômio de grau `n-1`, não deveria sobrar nenhuma informação sobre
o ponto que falta (`x=0`, o segredo) — essa é a garantia teórica
"perfeita" do SSS.

**Objetivo:** demonstrar que essa promessa não se sustenta nesta
implementação específica e recuperar o segredo completo.

---

## 2. A vulnerabilidade

Código-fonte relevante do servidor original:

```python
class SecretSharing:
    def __init__(self, p: int, n: int, secret: int):
        self.p = p
        self.n = n
        self.poly = [secret] + [getRandomRange(0, self.p - 1) for _ in range(n - 1)]
```

`getRandomRange(a, b)` sorteia um inteiro em `[a, b-1]`. Logo,
`getRandomRange(0, self.p - 1)` sorteia coeficientes em `[0, p-2]` —
**o valor `p-1` nunca é sorteado**. É um erro de off-by-one (faltou
um `+1` no segundo argumento), mas com consequência séria: a
segurança "perfeita" do SSS depende dos coeficientes serem
uniformemente aleatórios em todo o corpo `Z/pZ`. Como isso não é
verdade aqui, informação sobre o segredo vaza.

---

## 3. Teoria necessária

### 3.1 Shamir Secret Sharing e interpolação de Lagrange

`k` pontos definem um único polinômio de grau `k-1`. Um segredo `S`
é colocado como termo independente (`f(0) = S`), e cada participante
recebe um ponto `(x_i, f(x_i))`. Com `k` pontos, reconstrói-se o
polinômio via **interpolação de Lagrange**; com menos que `k`, em
teoria, zero informação vaza.

### 3.2 Por que o valor `p-1` vira uma "testemunha" de erro

O raciocínio central do ataque:

> Se chutarmos um valor `a0` para o segredo, e usarmos esse chute
> junto aos `n-1` pontos reais recebidos para reconstruir o
> **polinômio completo** (todos os coeficientes, via Lagrange) — e
> se **qualquer** coeficiente reconstruído der exatamente `p-1` —
> então esse chute está **errado**, porque a implementação real
> nunca produz `p-1` em nenhum coeficiente.

Repetindo esse teste para todo `a0` em `[0, p)`, e pedindo shares
novas quando sobra mais de um candidato, converge-se para um único
valor: `secret mod p`.

### 3.3 Escolha de módulos e reconstrução via CRT

Cada rodada só recupera `secret mod p` para um `p` específico — uma
fração da informação. Pelo **Teorema Chinês do Resto (CRT)**, com
`secret mod p_1, secret mod p_2, ...` para primos coprimos entre si,
reconstrói-se o segredo completo **desde que o produto de todos os
primos ultrapasse o valor máximo possível do segredo** (aqui,
`2^256`, por serem 32 bytes).

---

## 4. Ambiente, dependências e execução

**Não é necessário Docker.** A vulnerabilidade está inteiramente na
lógica do `SecretSharing`, não em nada específico de rede — por
isso, o servidor foi reimplementado fielmente (bug incluído) e
simulado como uma **função Python local**, em vez de socket/container.

**Dependências:** nenhuma biblioteca externa — Python 3.8+ puro (o
inverso modular usa `pow(a, -1, p)`, nativo desde essa versão; a
geração de primos na extensão usa um teste de primalidade de
Miller-Rabin escrito do zero).

**Arquivos:**
- `demo_share_attack.py` — ataque principal, com um segredo pequeno
  de demonstração (execução em segundos).
- `demo_share_attack_texto.py` — extensão que aceita qualquer
  texto/senha, converte automaticamente para inteiro e calcula
  sozinha quantos primos são necessários. **Importa funções de
  `demo_share_attack.py`, então os dois arquivos precisam estar na
  mesma pasta** para rodar.

**Como rodar:**

**Linux / macOS:**

```bash
python3 --version   # confirme 3.8 ou mais recente

# ataque principal (rápido, ~0.3s)
python3 demo_share_attack.py

# extensão com texto/senha arbitrária (mais lento, escala com o tamanho)
python3 demo_share_attack_texto.py "sua frase ou senha aqui"
```

**Windows (PowerShell ou Prompt de Comando):**

```powershell
python --version    # confirme 3.8 ou mais recente (use "python3" se "python" não for reconhecido)

# ataque principal (rápido, ~0.3s)
python demo_share_attack.py

# extensão com texto/senha arbitrária (mais lento, escala com o tamanho)
python demo_share_attack_texto.py "sua frase ou senha aqui"
```

> No Windows, se a senha/frase tiver espaços, mantenha as aspas duplas
> (`"sua frase aqui"`) — o PowerShell e o CMD exigem isso para tratar
> como um único argumento, assim como o exemplo do Linux/macOS.
>
> Em ambos os sistemas, lembre-se: `demo_share_attack_texto.py`
> importa funções de `demo_share_attack.py`, então os dois arquivos
> precisam estar na mesma pasta antes de rodar.

---

## 5. Estrutura e explicação do código

### `demo_share_attack.py`

1. **`SecretSharing`** — cópia fiel do servidor original, bug incluído.
2. **`servidor_local()`** — simula o servidor como função: devolve
   `n-1` shares, igual ao `shares[:-1]` do original.
3. **`lagrange_interpola_completo()`** — reconstrói **todos** os
   coeficientes do polinômio (não só `f(0)`), necessário para
   localizar a testemunha `p-1`.
4. **`recupera_secret_mod_p()`** — núcleo do ataque: testa cada
   candidato `a0`, descarta quem produz a testemunha `p-1`, repete
   consultas até sobrar um único candidato.
5. **`crt()`** — junta os resultados de vários primos num segredo único.
6. **Bloco principal** — executa tudo de ponta a ponta e confere o
   resultado contra o segredo real.

### `demo_share_attack_texto.py`

Reaproveita `servidor_local`, `recupera_secret_mod_p` e `crt` do
script principal e adiciona:
- `texto_para_inteiro()` — converte a entrada em texto para inteiro,
  do mesmo jeito que o desafio real converte bytes aleatórios.
- `eh_primo()` / `proximo_primo()` — Miller-Rabin implementado do
  zero, sem depender de bibliotecas externas.
- `gera_primos_suficientes()` — calcula automaticamente quantos
  primos são necessários até o produto ultrapassar o segredo.
- Ao final, reconstrói o texto original a partir do segredo
  recuperado, fechando o ciclo de forma visual.

---

## 6. Evidência de reprodução

Saída real da execução de `demo_share_attack.py`:

```
Segredo real (para conferencia): 123456789
Primos escolhidos: [17, 19, 23, 29, 31, 37, 41]
Produto dos primos: 10131543907

  p= 17 -> secret mod p =   1 (esperado   1) [OK] (8 consulta(s))
  p= 19 -> secret mod p =  14 (esperado  14) [OK] (5 consulta(s))
  p= 23 -> secret mod p =  11 (esperado  11) [OK] (6 consulta(s))
  p= 29 -> secret mod p =  19 (esperado  19) [OK] (14 consulta(s))
  p= 31 -> secret mod p =   2 (esperado   2) [OK] (19 consulta(s))
  p= 37 -> secret mod p =  36 (esperado  36) [OK] (13 consulta(s))
  p= 41 -> secret mod p =   8 (esperado   8) [OK] (20 consulta(s))

Segredo reconstruido via CRT: 123456789
Segredo real:                 123456789

[SUCESSO] O ataque recuperou o segredo completo, ponta a ponta.
tempo total: 0.26 s
```

Evidência adicional de escala real, com `demo_share_attack_texto.py`:

| Entrada | Tamanho | Primos necessários | Tempo |
|---|---|---|---|
| `"senha de teste 2026"` (20 chars) | 151 bits | 26 primos | ~5,4s |
| 32 bytes (tamanho real do desafio original) | 256 bits | ~40 primos | ~17-18s |

Em ambos os casos o texto/segredo de entrada foi recuperado
corretamente e conferido byte a byte contra o valor original.

---

## 7. Contribuições próprias do grupo

- **Reprodução sem Sage e sem Docker**: o write-up de referência
  (0xAtticus) usa SageMath e otimização de pipelining contra um
  servidor de rede real, com timeout de 30s. Reimplementamos a
  interpolação de Lagrange em Python puro e simulamos o servidor
  localmente — eliminando a necessidade de pipelining, já que não há
  latência de rede.
- **Explicação didática ampliada da testemunha `p-1`** (Seção 3.2),
  detalhando o raciocínio passo a passo para quem não tem
  familiaridade prévia com SSS.
- **Automação da escolha de primos + medição de custo em escala
  real** (`demo_share_attack_texto.py`), incluindo teste com
  segredo do mesmo tamanho do desafio original (32 bytes / 256 bits),
  com tempos documentados na Seção 6.
- **Zero dependências externas** em ambos os scripts, inclusive na
  geração de primos (Miller-Rabin implementado do zero, no lugar de
  bibliotecas como `sympy`).

---

## 8. Referências

- Código-fonte original do desafio: repositório de **maple3142**
  (autor), *"HITCON CTF 2023 / Share"*.
- Cópia preservada com Dockerfile: [`cryptohack/ctf_archive`](https://github.com/cryptohack/ctf_archive/tree/main/HITCONCTF-2023-Share).
- Write-up de referência: **0xAtticus**, *"[HITCON 2023] Share
  write-up"* — explica a vulnerabilidade original e apresenta uma
  solução em Sage com pipelining contra o servidor real.
- Assistência de IA: **Claude (Anthropic)** foi utilizado como
  ferramenta de apoio para (1) reimplementar a classe `SecretSharing`
  original em Python, preservando fielmente a lógica e o bug do
  servidor, adaptada para rodar como função local em vez de
  socket/servidor; e (2) converter a solução em SageMath do write-up
  de referência (uso de `GF(p)` e `lagrange_polynomial`) para uma
  reimplementação em Python puro (funções
  `lagrange_interpola_completo`, `poly_mul` e o teste de primalidade
  de Miller-Rabin em `demo_share_attack_texto.py`), eliminando a
  dependência de SageMath.
