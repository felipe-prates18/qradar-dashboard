#!/bin/bash
###############################################################################
# Script.......: cleanup_lucene.sh
# Autor........: Jason Pereira
# Empresa......: Asper
# Criado em....: 23/01/2026
#
# Descrição:
#   Script responsável pelo expurgo de índices Lucene antigos (events e flows)
#   no QRadar, com o objetivo de liberar espaço em disco na partição /store,
#   sem impactar a retenção de eventos ou flows.
#
# Uso:
#   ./cleanup_lucene.sh [dias]
#   Se "dias" não for informado, usa 15 como padrão.
#
# Observações:
#   - O expurgo afeta apenas os índices de busca (Lucene).
#   - Não remove eventos ou flows brutos.
#   - Execução controlada via arquivo de lock para evitar concorrência.
#   - Execução mensal (primeiro dia do mês) via cron.
#
# Referência IBM:
#   https://www.ibm.com/support/pages/qradar-delete-files-or-directories-gain-space-store-partition?view=full
#
# Atualizações:
#   - 07/08/2026 - Felipe Santos - Adicionado suporte a parâmetro de linha
#     de comando para definir o número de dias de retenção (mtime), com
#     validação de entrada e valor padrão de 15 dias quando não informado.
###############################################################################
set -u

# PATH "seguro" para execução via cron (evita "command not found")
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

LOGFILE="/var/log/qradar/cleanup_lucene.log"
LOCKFILE="/var/run/cleanup_lucene.lock"

# Dias de retenção: usa o parâmetro passado na chamada, ou 15 como padrão
DIAS="${1:-15}"

# Valida que o parâmetro é um número inteiro positivo
if ! [[ "$DIAS" =~ ^[0-9]+$ ]]; then
  echo "$(date) - Parâmetro inválido: '$DIAS'. Informe um número inteiro de dias." >> "$LOGFILE"
  exit 1
fi

# Garante que o lock seja removido ao final
cleanup() { rm -f "$LOCKFILE"; }
trap cleanup EXIT INT TERM

echo "=================================================" >> "$LOGFILE"
echo "$(date) - Iniciando expurgo de índices Lucene (Ariel) - retenção: $DIAS dias" >> "$LOGFILE"

# Evita execução concorrente
if [ -f "$LOCKFILE" ]; then
  echo "$(date) - Script já está em execução. Encerrando para evitar concorrência." >> "$LOGFILE"
  exit 1
fi
touch "$LOCKFILE"

# Execução do comando conforme KB da IBM, agora com dias parametrizados
find /store/ariel/{events,flows}/records/ -type d -name "lucene" -mtime +"$DIAS" -exec rm -Rfv {} \; >> "$LOGFILE" 2>&1

echo "$(date) - Expurgo finalizado" >> "$LOGFILE"