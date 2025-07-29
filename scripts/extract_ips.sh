#!/usr/bin/env bash
set -Eeuo pipefail

# Função de log
log() { 
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$(basename "$0")] $*" >&2
}

# Variáveis
MASSCAN_JSON="${1:-outputs/masscan/masscan.json}"
OUTPUT_DIR="outputs/masscan"
IPS_FILE="$OUTPUT_DIR/ips.txt"
PORTS_FILE="$OUTPUT_DIR/ports_summary.txt"

# Criar diretório se não existir
mkdir -p "$OUTPUT_DIR"

# Verificar se arquivo JSON existe
if [[ ! -f "$MASSCAN_JSON" ]]; then
    log "[ERROR] Arquivo não encontrado: $MASSCAN_JSON"
    exit 1
fi

# Verificar se JSON está válido
if ! jq empty "$MASSCAN_JSON" 2>/dev/null; then
    log "[ERROR] JSON inválido em: $MASSCAN_JSON"
    log "[INFO] Conteúdo do arquivo:"
    head -5 "$MASSCAN_JSON" >&2
    exit 1
fi

# Verificar se há dados
total_entries=$(jq '. | length' "$MASSCAN_JSON")
if [[ "$total_entries" == "0" ]]; then
    log "[WARN] Nenhuma entrada encontrada no JSON"
    touch "$IPS_FILE"
    exit 0
fi

log "[INFO] Extraindo IPs ativos de $MASSCAN_JSON"
log "[INFO] Total de entradas no JSON: $total_entries"

# Extrair IPs únicos
jq -r '.[] | select(.open) | .ip' "$MASSCAN_JSON" | \
    sort -u -V > "$IPS_FILE"

# Verificar resultado
if [[ -f "$IPS_FILE" ]]; then
    ip_count=$(wc -l < "$IPS_FILE")
    log "[OK] Extraídos $ip_count IPs ativos para: $IPS_FILE"
    
    # Mostrar primeiros IPs como exemplo
    if [[ $ip_count -gt 0 ]]; then
        log "[INFO] Primeiros IPs:"
        head -5 "$IPS_FILE" | while read -r ip; do
            log "  - $ip"
        done
        [[ $ip_count -gt 5 ]] && log "  ... e mais $((ip_count - 5)) IPs"
        
        # Gerar resumo de portas
        log "[INFO] Gerando resumo de portas..."
        {
            echo "# Resumo de Portas Descobertas"
            echo "# Formato: COUNT PORT/PROTOCOL"
            echo "# Gerado em: $(date)"
            echo
            jq -r '.[] | select(.open) | "\(.port)/\(.proto)"' "$MASSCAN_JSON" | \
                sort | uniq -c | sort -nr
        } > "$PORTS_FILE"
        
        log "[INFO] Resumo de portas salvo em: $PORTS_FILE"
        
        # Mostrar top 5 portas
        log "[INFO] Top 5 portas mais comuns:"
        tail -n +5 "$PORTS_FILE" | head -5 | while read -r count port; do
            log "  - $port: $count hosts"
        done
        
    else
        log "[WARN] Nenhum IP ativo encontrado"
        echo "# Nenhum IP ativo encontrado em $(date)" > "$PORTS_FILE"
    fi
else
    log "[ERROR] Falha ao criar arquivo: $IPS_FILE"
    exit 1
fi

# Gerar estatísticas adicionais
if [[ $ip_count -gt 0 ]]; then
    stats_file="$OUTPUT_DIR/scan_stats.txt"
    {
        echo "=== Estatísticas do Scan Masscan ==="
        echo "Data: $(date)"
        echo "Arquivo fonte: $MASSCAN_JSON"
        echo
        echo "Total de entradas: $total_entries"
        echo "IPs únicos ativos: $ip_count"
        echo "Portas únicas: $(jq -r '.[] | select(.open) | .port' "$MASSCAN_JSON" | sort -u | wc -l)"
        echo "Protocolos: $(jq -r '.[] | select(.open) | .proto' "$MASSCAN_JSON" | sort -u | tr '\n' ' ')"
        echo
        echo "=== Distribuição por Protocolo ==="
        jq -r '.[] | select(.open) | .proto' "$MASSCAN_JSON" | sort | uniq -c | sort -nr
    } > "$stats_file"
    
    log "[INFO] Estatísticas salvas em: $stats_file"
fi

log "[SUCCESS] Extração de IPs concluída com sucesso!"