# IA Module - Phase 0 Brief

## Objetivo da Demo
- **Foco funcional**: Demonstrar como o módulo de IA acelera a análise de CVEs, sugere passos de exploração controlada e gera briefing de mitigação integrado aos dados do ARPIA.
- **Perfil do público-alvo**: Equipe técnica do cliente (analistas de segurança, pentesters internos) e decisores que acompanham relatórios do ARPIA.
- **Benefício esperado**: Reduzir o tempo entre a identificação do achado e a decisão de resposta, oferecendo guidance acionável baseado nos artefatos coletados pelo ARPIA.

## Provedor de IA Preferencial
| Provedor | Situação de contrato | Observações |
|----------|----------------------|-------------|
| OpenAI   | Utilizar plano self-service (pay-as-you-go) | Disponibilidade imediata, modelos maduros, suporte a funções/RAG |
| Azure OpenAI | Não aplicado para a demo | Exige onboarding corporativo; manter como opção futura |
| Outro | Não considerado | Foque na rapidez da demo inicial |

- **Decisão prévia**: Utilizar OpenAI na demo, priorizando modelos multimodais/textuais com bom custo-benefício.
- **Modelos candidatos**: `gpt-4o-mini` (respostas rápidas) e `gpt-4o` (quando precisar de saída mais detalhada).

## Escopo Funcional da Demo
1. **Análise de CVE Crítica**: usuário seleciona uma CVE presente em `VulnerabilityFinding`; o agente retorna recomendação de mitigação e passos de validação.
2. **Exploração Orientada**: a partir de uma porta/serviço exposto identificado em `ScanSession`, o agente sugere scripts do repositório ARPIA para aprofundar a exploração controlada.
3. **Resumo Executivo**: geração de briefing em linguagem acessível (bullet points) para apresentar ao cliente, usando dados do projeto atual.

## Restrições / Premissas
- Dados sanitizados gerados a partir de projetos de laboratório (sem PII real).
- Ambiente apresentado: instância de staging do ARPIA com dataset controlado.
- Limite de tempo da demo: 20 minutos (15 de apresentação + 5 de perguntas).

## Métricas de Sucesso
- Tempo máximo de resposta do agente: < 8 segundos para perguntas padrão.
- Pelo menos 2 dos 3 casos de uso apresentados com avaliação “satisfeito” pelos participantes.
- Feedback qualitativo evidenciando que o agente entende a estrutura do ARPIA (referencia achados, scripts, relatórios).

## Próximos Passos Imediatos
- Validar internamente os dados sanitizados que serão carregados (dataset demo pronto).
- Configurar conta OpenAI e registrar chave API em ambiente seguro.
- Marcar sessão de ensaio interno (rodar os 3 casos de uso) antes da demo final.
