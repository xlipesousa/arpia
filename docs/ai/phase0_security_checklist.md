# IA Module - Security & Privacy Checklist (Phase 0)

## Scope & Data Handling
- [x] Dados usados na demo são fictícios ou anonimizados.
- [x] Lista de campos sensíveis revisada e removida (credenciais, tokens, PII).
- [x] Volume máximo de dados por requisição definido (até 4k tokens por chamada).
- [x] Logs do ARPIA avaliados para evitar vazamento de segredos.

## Provedor & Compliance
- [x] Provedor selecionado possui contrato ativo ou aprovação legal (OpenAI pay-as-you-go).
- [x] Regiões de processamento revisadas (modelo roda em ; demo não usa dados sensíveis).
- [x] Termos de uso e políticas de privacidade revisados e aceitos.
- [ ] Custos estimados para a demo aprovados pelo financeiro (pendente validação interna, custo estimado < USD 50).

## Operação da Demo
- [x] Ambiente de demonstração isolado (staging / sandbox) preparado.
- [x] Acesso limitado apenas aos usuários envolvidos na demo.
- [x] Métricas de uso monitoradas (requisições, tokens, custos via dashboard OpenAI).
- [ ] Plano de contingência caso o provedor fique indisponível (pendente fallback, sugerir mock local).

## Observabilidade & Auditoria
- [x] Logs de prompts/respostas armazenados com retenção definida (7 dias para demo).
- [ ] Evento de auditoria criado para cada interação com o agente (planejado via middleware).
- [ ] Alertas configurados para falhas ou custos inesperados (configurar webhook de alerta).

## Aprovações Finais
- [ ] Responsável de segurança aprovou o checklist (assinar na véspera da demo).
- [ ] Responsável de produto aprovou o escopo da demo (agendar revisão breve).
- [ ] Equipe jurídica/compliance deu parecer positivo (informar uso de dados fictícios).
- [ ] Go/no-go registrado com data e participantes (usar planilha de controle da demo).
