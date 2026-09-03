# HITCON CTF 2023 — Share (Crypto)

Write-up e reprodução do desafio **Share**, categoria Cripto do HITCON CTF 2023, desenvolvido como avaliação (E1) da disciplina **Segurança Cibernética (CCO-04.2.01)** — PPGCC, UFSCar.

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

Esse foi o desafio de criptografia, desenvolvido por maple3142. "Ele foi o mais resolvido e o mais acessível de todos os desafios de criptografia do HITCON 2023 CTF"(0XATTICUS, 2023, tradução nossa). Nos artefatos fornecidos há a seguinte descrição:

"I hope I actually implemented Shamir Secret Sharing correctly this year. I am pretty sure you won't be able to guess my secret even when I give you all but one share"(0XATTICUS, 2023).

O desafio implementa **Shamir Secret Sharing (SSS)**: um servidor sorteia um segredo de 32 bytes (256 bits) e permite ao cliente solicitar "pedaços" (*shares*) desse segredo, escolhendo dois parâmetros — um primo `p` e uma quantidade `n` de pedaços (`int(13.37) < n < p` no código original, que equivale a `13 < n < p` — `int()` trunca `13.37` para `13`, provável trocadilho do autor com "1337"/"leet"). O servidor gera um polinômio aleatório de grau `n-1`, com o segredo como termo independente, e devolve `n-1` pontos desse polinômio.

**Promessa de segurança do desafio:** com `n-1` pontos de um polinômio de grau `n-1`, não deveria sobrar nenhuma informação sobre o ponto que falta (`x=0`, o segredo) — essa é a garantia teórica "perfeita" do SSS.

**Objetivo:** demonstrar que essa promessa não se sustenta nesta implementação específica e recuperar o segredo completo.

---

## 2. A vulnerabilidade

O Código-fonte à seguir, relevante do servidor original, evidencia a vulnerabilidade:

```python
class SecretSharing:
    def __init__(self, p: int, n: int, secret: int):
        self.p = p
        self.n = n
        self.poly = [secret] + [getRandomRange(0, self.p - 1) for _ in range(n - 1)]
```

A função `getRandomRange(a, b)`, utilizada nessa implementação gera um número inteiro aleatório no intervalo `[a, b-1]`, ou seja, o segundo limite é exclusivo.

Assim, quando o código executa: `getRandomRange(0, self.p - 1)`, os valores possíveis são:`0, 1, 2, ..., p-2`, nunca sendo sorteado `p-1`.
No SSS, os coeficientes do polinômio utilizado para construir os compartilhamentos devem ser escolhidos uniformemente em todo o corpo finito `Z/pZ`, ou seja, cada valor entre `0` e `p-1` deve possuir a mesma probabilidade de ser escolhido.

Essa propriedade é importante porque é justamente a aleatoriedade dos coeficientes que impede que um participante, ou um conjunto de participantes abaixo do limiar necessário, obtenha informação sobre o segredo.

Na implementação analisada, entretanto, o valor `p-1` é sistematicamente excluído do processo de geração dos coeficientes. Portanto, a distribuição utilizada não corresponde à distribuição uniforme exigida pelo esquema teórico.

O problema, portanto, não está simplesmente no fato de um valor estar faltando. A consequência mais importante é que a implementação deixa de satisfazer uma das premissas matemáticas utilizadas para garantir a segurança perfeita do SSS.

---

## 3. Referencial Teórico

### 3.1 Shamir Secret Sharing

O Shamir Secret Sharing (SSS) é um esquema criptográfico de compartilhamento de segredos proposto por Adi Shamir em 1979. Seu objetivo é dividir um segredo em n partes, denominadas shares, de modo que seja necessário um número mínimo k dessas partes para reconstruí-lo. Esse número k é denominado limiar (threshold). Uma das principais propriedades do esquema é que qualquer conjunto com menos de k shares não deve fornecer nenhuma informação sobre o segredo.
O funcionamento do SSS baseia-se na representação do segredo como o termo independente de um polinômio de grau `k - 1`, definido sobre um corpo finito: 

$$
f(x) = a_0 + a_1x + a_2x^2 + \cdots + a_{k-1}x^{k-1}
$$

Nesse polinômio, \(a_0\) representa o segredo, enquanto os demais coeficientes \(a_1, a_2, \ldots, a_{k-1}\) são escolhidos aleatoriamente. Como \(f(0) = a_0\), o segredo corresponde ao valor do polinômio no ponto \(x=0\).

Para gerar os shares, são selecionados valores distintos de \(x\) e calculados os respectivos valores de \(f(x)\). Cada share é, portanto, representado por um ponto do polinômio:
$$
(x_i, f(x_i))
$$

A reconstrução do segredo ocorre a partir de pelo menos k pontos distintos, utilizando interpolação polinomial. Como um polinômio de grau `k-1` é unicamente determinado por `k` pontos distintos, esses pontos são suficientes para reconstruir o polinômio e, consequentemente, obter o segredo por meio de \(f(0)\).

A segurança do método está justamente na quantidade mínima de pontos necessária para determinar o polinômio. Com menos de `k` shares, existem múltiplos polinômios de grau `k-1` que são compatíveis com os pontos conhecidos. Quando os coeficientes são escolhidos uniformemente e de forma aleatória no corpo finito utilizado, cada possível valor para \(a_0\) é igualmente compatível com os shares disponíveis. Dessa forma, os participantes que possuem menos de k partes não obtêm informação sobre o segredo. Essa propriedade é conhecida como segurança perfeita.

No desafio analisado neste trabalho, são fornecidos `n-1` shares de um polinômio de grau `n-1`. Portanto, considerando um esquema SSS corretamente implementado com limiar n, essa quantidade de informações seria insuficiente para reconstruir o polinômio e determinar o segredo.

Entretanto, a implementação apresenta uma falha na geração aleatória dos coeficientes do polinômio. Essa falha faz com que os coeficientes não sejam selecionados uniformemente em todo o corpo finito, violando uma das condições necessárias para a garantia teórica de segurança perfeita do SSS. Consequentemente, embora o número de shares disponíveis seja inferior ao limiar necessário para a reconstrução convencional, a implementação pode apresentar um vazamento de informação sobre o segredo.

A partir dessa vulnerabilidade, torna-se possível explorar a distribuição não uniforme dos coeficientes para obter informações que não deveriam estar disponíveis com apenas `n-1` shares. A natureza dessa falha e o método utilizado para explorá-la serão demonstrados nas etapas seguintes.


### 3.2 Interpolação de Lagrange e aritmética modular

A reconstrução do segredo a partir dos shares é realizada por meio da interpolação de Lagrange. Dado um conjunto suficiente de pontos, a técnica permite calcular o valor do polinômio em uma determinada posição sem a necessidade de resolver diretamente todos os seus coeficientes. Como o segredo corresponde a $f(0)$, basta calcular:

$$
f(0) = \sum_{i=1}^{k} y_i L_i(0)
$$

onde $y_i$ representa o valor de cada share e $L_i(0)$ é o peso correspondente ao ponto.

No SSS essa interpolação utiliza aritmética modular, o que significa que as operações são realizadas considerando um módulo $p$ e os resultados são representados entre 0 e $p - 1$. Dois valores são congruentes módulo $p$ quando possuem o mesmo resto:

$a \equiv b \pmod p$

O uso de um módulo primo é importante porque garante a existência de inversos multiplicativos para todos os valores diferentes de zero. O inverso de $a$ módulo $p$ é um valor $a^{-1}$ que satisfaz:

$a \cdot a^{-1} \equiv 1 \pmod p$

Assim, as divisões necessárias na interpolação podem ser realizadas como multiplicações pelo inverso modular. Por exemplo, para módulo 7 o inverso de 3 é 5, pois:

$3 \cdot 5 \equiv 1 \pmod 7$

Além da reconstrução em um único módulo, o desafio utiliza diferentes valores de $p$. Para cada módulo, é possível obter uma informação sobre o segredo na forma de um resíduo:

$S \equiv r_i \pmod{p_i}$

Essas informações podem ser combinadas utilizando o Teorema Chinês de Resto (CRT). Quando os módulos são coprimos entre si, o CRT permite determinar um único valor módulo o produto dos módulos:

$P = p_1p_2\cdots p_n$

Como os $p_i$ utilizados são primos distintos, eles são coprimos entre si. Portanto, ao obter resíduos suficientes e garantir que $P > 2^{256}$ é possível determinar unicamente o segredo de 32 bytes, cujo valor está no intervalo $0 \leq S < 2^{256}$.

Dessa forma, a interpolação de Lagrange permite trabalhar com os shares dentro de cada módulo, enquanto o CRT permite combinar as informações obtidas em diferentes módulos para reconstruir o segredo completo.

### 3.3 Por que o valor `p-1` vira uma "testemunha" de erro

O raciocínio central do ataque:

> Se chutarmos um valor `a0` para o segredo, e usarmos esse chute junto aos `n-1` pontos reais recebidos para reconstruir o **polinômio completo** (todos os coeficientes, via Lagrange) — e se **qualquer** coeficiente reconstruído der exatamente `p-1` — então esse chute está **errado**, porque a implementação real nunca produz `p-1` em nenhum coeficiente.

Repetindo esse teste para todo `a0` em `[0, p)`, e pedindo shares novas quando sobra mais de um candidato, converge-se para um único valor: `secret mod p`.

### 3.4 Escolha de módulos e reconstrução via CRT 

Em cada rodada do ataque, é possível obter uma informação parcial sobre o segredo na forma de secret mod p, para um determinado primo \(p\). Esse resultado representa apenas o resto da divisão do segredo por esse módulo e, isoladamente, não é suficiente para determinar o valor completo do segredo.

Para combinar essas informações parciais, utiliza-se o Teorema Chinês do Resto (CRT — Chinese Remainder Theorem). Considerando diferentes primos \(p_1, p_2, \ldots, p_m\), coprimos entre si, e conhecendo os respectivos valores:

$$
\mathit{secret} \bmod p_1, \quad \mathit{secret} \bmod p_2, \quad \ldots, \quad \mathit{secret} \bmod p_m
$$

o CRT permite reconstruir um único valor de \(secret\) módulo:

$$
P = p_1 p_2 \cdots p_m
$$

A reconstrução corresponde ao segredo completo quando o produto dos módulos utilizados é maior que o maior valor possível para o segredo. Neste desafio, o segredo possui 32 bytes, portanto seu valor máximo está limitado a \(2^{256}-1\). Assim, é suficiente selecionar módulos primos de modo que:

$$
p_1 p_2 \cdots p_m > 2^{256}
$$

Dessa forma, embora cada rodada forneça apenas uma fração da informação sobre o segredo, a combinação dos resultados obtidos para diferentes módulos permite reconstruir unicamente o valor original. Esse processo constitui a etapa final do ataque: obter sucessivos valores secret mod p, acumular informação suficiente e utilizar o CRT para recuperar o segredo completo.​

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

O script agora imprime, para cada primo, uma tabela rodada a rodada mostrando os candidatos sendo eliminados até sobrar um único valor — útil tanto como evidência mais detalhada quanto como apoio visual na apresentação. Trecho representativo da saída real (primo `p=17` completo; os demais primos seguem o mesmo formato, omitidos aqui por espaço — a saída completa tem ~100 linhas e pode ser reproduzida rodando o script):

```
Segredo real (para conferencia): 123456789
Primos escolhidos: [17, 19, 23, 29, 31, 37, 41]
Produto dos primos: 10131543907

  p=17:
    Inicio: 17 candidatos possiveis -> [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    Rodada 1: eliminou 10 candidato(s) [2, 3, 4, 5, 6, 8, 10, 11, 13, 15] | sobraram 7 -> [0, 1, 7, 9, 12, 14, 16]
    Rodada 2: eliminou 3 candidato(s) [0, 7, 16] | sobraram 4 -> [1, 9, 12, 14]
    Rodada 3: eliminou 2 candidato(s) [9, 12] | sobraram 2 -> [1, 14]
    Rodada 4: eliminou 0 candidato(s) [] | sobraram 2 -> [1, 14]
    Rodada 5: eliminou 0 candidato(s) [] | sobraram 2 -> [1, 14]
    Rodada 6: eliminou 0 candidato(s) [] | sobraram 2 -> [1, 14]
    Rodada 7: eliminou 0 candidato(s) [] | sobraram 2 -> [1, 14]
    Rodada 8: eliminou 1 candidato(s) [14] | sobraram 1 -> [1]
    -> secret mod p =   1 (esperado   1) [OK] (8 consulta(s))

  [... primos 19, 23, 29, 31, 37, 41 seguem o mesmo formato ...]

Segredo reconstruido via CRT: 123456789
Segredo real:                 123456789

[SUCESSO] O ataque recuperou o segredo completo, ponta a ponta.
tempo total: 0.26 s
```

Resumo dos 7 primos (resultado final de cada tabela completa):

| Primo (`p`) | Resto (`secret mod p`) | Consultas até convergir |
|---|---|---|
| 17 | 1 | 8 |
| 19 | 14 | 5 |
| 23 | 11 | 6 |
| 29 | 19 | 14 |
| 31 | 2 | 19 |
| 37 | 36 | 13 |
| 41 | 8 | 20 |

**Nota sobre o número de consultas variar por primo:** o processo é probabilístico — um candidato errado só é eliminado quando o número impossível (`p-1`) aparece por acaso em algum coeficiente reconstruído naquela rodada. Às vezes isso demora mais (`p=31` precisou de 19 rodadas), às vezes menos (`p=19` precisou de só 5) — não é um erro, é o comportamento esperado do ataque.

A tabela detalhada só é impressa para primos pequenos (`p <= 50`, via o parâmetro `verboso` de `recupera_secret_mod_p`), para não poluir a saída caso o script seja usado com primos maiores.

Evidência adicional de escala real, com `demo_share_attack_texto.py`:

| Entrada | Tamanho | Primos necessários | Tempo |
|---|---|---|---|
| `"senha de teste 2026"` (20 chars) | 151 bits | 26 primos | ~5,4s |
| 32 bytes (tamanho real do desafio original) | 256 bits | ~40 primos | ~17-18s |

Em ambos os casos o texto/segredo de entrada foi recuperado corretamente e conferido byte a byte contra o valor original.

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

- Código-fonte original do desafio: repositório de **maple3142** (autor), *"HITCON CTF 2023 / Share"*.
- Cópia preservada com Dockerfile: [`cryptohack/ctf_archive`](https://github.com/cryptohack/ctf_archive/tree/main/HITCONCTF-2023-Share).
- NIST Digital Library of Mathematical Functions. Interpolation. Seção 3.3. Disponível em <https://dlmf.nist.gov/3.3>. Acesso em 02/09/2026.
- SHAMIR, Adi. How to Share a Secret. Communications of the ACM, v. 22, n. 11, p. 612–613, 1979. DOI: 10.1145/359168.359176. Disponível em <https://dl.acm.org/doi/10.1145/359168.359176>. Acesso em 02/09/2026.
- Weisstein, Eric W. Chinese Remainder Theorem. Wolfram MathWorld. Disponível em <https://mathworld.wolfram.com/ChineseRemainderTheorem.html>. Acesso em 02/09/2026.
- Write-up de referência: **0xAtticus**, *"[HITCON 2023] Share write-up"* — explica a vulnerabilidade original e apresenta uma solução em Sage com pipelining contra o servidor real.
- Assistência de IA: **Claude (Anthropic)** foi utilizado como ferramenta de apoio para (1) reimplementar a classe `SecretSharing` original em Python, preservando fielmente a lógica e o bug do servidor, adaptada para rodar como função local em vez de socket/servidor; e (2) converter a solução em SageMath do write-up de referência (uso de `GF(p)` e `lagrange_polynomial`) para uma reimplementação em Python puro (funções `lagrange_interpola_completo`, `poly_mul` e o teste de primalidade de Miller-Rabin em `demo_share_attack_texto.py`), eliminando a dependência de SageMath.
