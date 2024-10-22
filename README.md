# Sistema de Pontuação de Privacidade

## Introdução
O sistema de pontuação de privacidade foi desenvolvido para avaliar a segurança e a privacidade de um site, considerando diferentes fatores que impactam a experiência do usuário. O objetivo é fornecer uma pontuação de 0 a 100, onde pontuações mais altas indicam maior privacidade.

## Objetivos
- **Avaliar a privacidade de um site**: O sistema deve calcular uma pontuação que represente a exposição do usuário a riscos de privacidade.
- **Fornecer feedback ao usuário**: Informar os usuários sobre vulnerabilidades detectadas e permitir que tomem decisões informadas.

## Fatores de Avaliação
O sistema considera os seguintes fatores, cada um com uma penalização específica:

### Conexões de Terceiros:
- **Descrição**: Número de conexões de terceiros detectadas no site.
- **Penalização**: 2 pontos por conexão, com um máximo de 20 pontos.
- **Justificativa**: Conexões de terceiros podem comprometer a privacidade do usuário, pois permitem o rastreamento de comportamentos online.

### Cookies:
- **Descrição**: Total de cookies utilizados pelo site.
- **Penalização**: 1 pontos por cookie, com um máximo de 20 pontos.
- **Justificativa**: Cookies são frequentemente utilizados para rastreamento e personalização de anúncios. Uma penalização proporcional ao número de cookies ajuda a quantificar o potencial de invasão de privacidade, uma vez que o uso excessivo pode levar a práticas invasivas de coleta de dados.

### LocalStorage:
- **Descrição**: Dados armazenados localmente pelo site.
- **Penalização**: 3 pontos para cada 1024 caracteres armazenados, com um máximo de 15 pontos.
- **Justificativa**: O uso excessivo de `localStorage` pode levar ao armazenamento de informações sensíveis, aumentando o risco de exposição. O limite de 1024 caracteres reflete um uso moderado antes de penalizar, mantendo a experiência do usuário.

### Canvas Fingerprinting:
- **Descrição**: Detecção de técnicas de canvas fingerprinting.
- **Penalização**: 10 pontos se detectado.
- **Justificativa**: Canvas fingerprinting é uma técnica de rastreamento que utiliza as características únicas do hardware e software do usuário para identificá-lo de forma persistente. Esta técnica é considerada altamente invasiva, justificando uma penalização significativa em razão do potencial de violação da privacidade.

### Potencial Hijacking:
- **Descrição**: Detecção de potenciais ataques de hijacking.
- **Penalização**: 15 pontos se detectado.
- **Justificativa**: Ataques de hijacking representam um risco grave, pois podem comprometer a segurança e a privacidade do usuário, permitindo que um atacante tenha controle sobre a sessão do navegador. Essa penalização reflete a gravidade e a urgência da vulnerabilidade, já que a proteção contra tais ameaças é crucial para a segurança do usuário.


A construção desta API contou com o suporte do ChatGPT, uma ferramenta de inteligência artificial desenvolvida pela OpenAI, utilizada para fornecer sugestões, otimizações e esclarecimentos em diversas etapas do desenvolvimento, incluindo a definição de estrutura de dados, lógica de manipulação de cookies e boas práticas de programação.
