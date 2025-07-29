#!/usr/bin/env bash
set -Eeuo pipefail

# Função de log
log() { 
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$(basename "$0")] $*" >&2
}

# Variáveis
REPORT_DIR="outputs/reports"
SCAN_RESULTS_DIR="outputs/scan_results"
MASSCAN_DIR="outputs/masscan"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$REPORT_DIR/security_report_$TIMESTAMP.html"
JSON_REPORT="$REPORT_DIR/security_report_$TIMESTAMP.json"

# Criar diretório de relatórios
mkdir -p "$REPORT_DIR"

log "[INFO] Gerando relatório de segurança..."

# Verificar se há dados para processar
if [[ ! -d "$SCAN_RESULTS_DIR" ]] || [[ -z "$(ls -A "$SCAN_RESULTS_DIR" 2>/dev/null)" ]]; then
    log "[WARN] Nenhum resultado de scan encontrado"
    exit 0
fi

# Coletar estatísticas
collect_stats() {
    local total_ips=0
    local scanned_ips=0
    local total_vulns=0
    local critical_vulns=0
    local high_vulns=0
    local medium_vulns=0
    local low_vulns=0
    local open_ports=0
    
    # Contar IPs totais
    if [[ -f "$MASSCAN_DIR/ips.txt" ]]; then
        total_ips=$(wc -l < "$MASSCAN_DIR/ips.txt")
    fi
    
    # Contar IPs escaneados
    scanned_ips=$(find "$SCAN_RESULTS_DIR" -type d -mindepth 1 | wc -l)
    
    # Contar vulnerabilidades por severidade
    for nuclei_file in "$SCAN_RESULTS_DIR"/*/nuclei.json; do
        if [[ -s "$nuclei_file" ]]; then
            local file_vulns=$(jq length "$nuclei_file" 2>/dev/null || echo "0")
            total_vulns=$((total_vulns + file_vulns))
            
            # Contar por severidade
            critical_vulns=$((critical_vulns + $(jq '[.[] | select(.info.severity == "critical")] | length' "$nuclei_file" 2>/dev/null || echo "0")))
            high_vulns=$((high_vulns + $(jq '[.[] | select(.info.severity == "high")] | length' "$nuclei_file" 2>/dev/null || echo "0")))
            medium_vulns=$((medium_vulns + $(jq '[.[] | select(.info.severity == "medium")] | length' "$nuclei_file" 2>/dev/null || echo "0")))
            low_vulns=$((low_vulns + $(jq '[.[] | select(.info.severity == "low")] | length' "$nuclei_file" 2>/dev/null || echo "0")))
        fi
    done
    
    # Contar portas abertas
    for nmap_file in "$SCAN_RESULTS_DIR"/*/nmap.txt; do
        if [[ -s "$nmap_file" ]]; then
            local ports=$(grep -c "^[0-9].*open" "$nmap_file" 2>/dev/null || echo "0")
            open_ports=$((open_ports + ports))
        fi
    done
    
    # Retornar estatísticas
    echo "$total_ips|$scanned_ips|$total_vulns|$critical_vulns|$high_vulns|$medium_vulns|$low_vulns|$open_ports"
}

# Gerar relatório JSON
generate_json_report() {
    local stats="$1"
    IFS='|' read -r total_ips scanned_ips total_vulns critical_vulns high_vulns medium_vulns low_vulns open_ports <<< "$stats"
    
    local vulnerabilities="[]"
    local hosts="[]"
    
    # Coletar vulnerabilidades
    for ip_dir in "$SCAN_RESULTS_DIR"/*; do
        if [[ -d "$ip_dir" ]]; then
            local ip=$(basename "$ip_dir")
            local nuclei_file="$ip_dir/nuclei.json"
            local nmap_file="$ip_dir/nmap.txt"
            
            # Adicionar host info
            local host_ports="[]"
            if [[ -s "$nmap_file" ]]; then
                host_ports=$(grep "^[0-9].*open" "$nmap_file" 2>/dev/null | jq -R -s 'split("\n") | map(select(length > 0))' || echo "[]")
            fi
            
            # Adicionar vulnerabilidades do host
            if [[ -s "$nuclei_file" ]]; then
                # Adicionar IP a cada vulnerabilidade
                local host_vulns=$(jq --arg ip "$ip" 'map(. + {"host": $ip})' "$nuclei_file" 2>/dev/null || echo "[]")
                vulnerabilities=$(echo "$vulnerabilities" | jq --argjson host_vulns "$host_vulns" '. + $host_vulns')
            fi
            
            # Adicionar info do host
            local host_info=$(jq -n \
                --arg ip "$ip" \
                --argjson ports "$host_ports" \
                --arg nmap_file "$nmap_file" \
                --arg nuclei_file "$nuclei_file" \
                '{
                    ip: $ip,
                    open_ports: ($ports | length),
                    ports: $ports,
                    has_nmap_results: ($nmap_file != ""),
                    has_nuclei_results: ($nuclei_file != ""),
                    vulnerabilities: 0
                }')
            
            if [[ -s "$nuclei_file" ]]; then
                local vuln_count=$(jq length "$nuclei_file" 2>/dev/null || echo "0")
                host_info=$(echo "$host_info" | jq --argjson count "$vuln_count" '.vulnerabilities = $count')
            fi
            
            hosts=$(echo "$hosts" | jq --argjson host "$host_info" '. + [$host]')
        fi
    done
    
    # Gerar relatório final
    jq -n \
        --arg timestamp "$(date -Iseconds)" \
        --arg scan_date "$(date)" \
        --argjson total_ips "$total_ips" \
        --argjson scanned_ips "$scanned_ips" \
        --argjson total_vulns "$total_vulns" \
        --argjson critical_vulns "$critical_vulns" \
        --argjson high_vulns "$high_vulns" \
        --argjson medium_vulns "$medium_vulns" \
        --argjson low_vulns "$low_vulns" \
        --argjson open_ports "$open_ports" \
        --argjson vulnerabilities "$vulnerabilities" \
        --argjson hosts "$hosts" \
        '{
            report_info: {
                generated: $timestamp,
                scan_date: $scan_date,
                tool: "IzysScan",
                version: "1.0"
            },
            summary: {
                total_ips: $total_ips,
                scanned_ips: $scanned_ips,
                total_vulnerabilities: $total_vulns,
                total_open_ports: $open_ports,
                severity_breakdown: {
                    critical: $critical_vulns,
                    high: $high_vulns,
                    medium: $medium_vulns,
                    low: $low_vulns
                }
            },
            hosts: $hosts,
            vulnerabilities: $vulnerabilities
        }' > "$JSON_REPORT"
}

# Gerar relatório HTML
generate_html_report() {
    local stats="$1"
    IFS='|' read -r total_ips scanned_ips total_vulns critical_vulns high_vulns medium_vulns low_vulns open_ports <<< "$stats"
    
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IzysScan Security Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; }
        .stat-card { background: #f8f9fa; border-radius: 10px; padding: 20px; text-align: center; border-left: 4px solid #667eea; }
        .stat-card.critical { border-left-color: #dc3545; }
        .stat-card.high { border-left-color: #fd7e14; }
        .stat-card.medium { border-left-color: #ffc107; }
        .stat-card.low { border-left-color: #28a745; }
        .stat-number { font-size: 2.5em; font-weight: bold; margin: 0; }
        .stat-label { color: #666; margin-top: 5px; }
        .content { padding: 30px; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        .vulnerability { background: #fff; border: 1px solid #ddd; border-radius: 5px; margin: 10px 0; padding: 15px; }
        .vulnerability.critical { border-left: 4px solid #dc3545; }
        .vulnerability.high { border-left: 4px solid #fd7e14; }
        .vulnerability.medium { border-left: 4px solid #ffc107; }
        .vulnerability.low { border-left: 4px solid #28a745; }
        .vuln-title { font-weight: bold; color: #333; }
        .vuln-details { color: #666; margin-top: 5px; }
        .host-section { background: #f8f9fa; border-radius: 5px; padding: 20px; margin: 15px 0; }
        .host-title { font-weight: bold; color: #333; font-size: 1.2em; }
        .port { display: inline-block; background: #e9ecef; padding: 2px 8px; border-radius: 3px; margin: 2px; font-size: 0.9em; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; border-top: 1px solid #ddd; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ IzysScan Security Report</h1>
            <p>Relatório gerado em $(date '+%d/%m/%Y às %H:%M:%S')</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">$total_ips</div>
                <div class="stat-label">IPs Descobertos</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$scanned_ips</div>
                <div class="stat-label">IPs Escaneados</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$open_ports</div>
                <div class="stat-label">Portas Abertas</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$total_vulns</div>
                <div class="stat-label">Vulnerabilidades</div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card critical">
                <div class="stat-number">$critical_vulns</div>
                <div class="stat-label">Críticas</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">$high_vulns</div>
                <div class="stat-label">Altas</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">$medium_vulns</div>
                <div class="stat-label">Médias</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">$low_vulns</div>
                <div class="stat-label">Baixas</div>
            </div>
        </div>
        
        <div class="content">
EOF

    # Adicionar seção de vulnerabilidades críticas
    if [[ $critical_vulns -gt 0 ]] || [[ $high_vulns -gt 0 ]]; then
        cat >> "$REPORT_FILE" << EOF
            <div class="section">
                <h2>🚨 Vulnerabilidades Críticas e Altas</h2>
EOF
        
        for nuclei_file in "$SCAN_RESULTS_DIR"/*/nuclei.json; do
            if [[ -s "$nuclei_file" ]]; then
                local ip=$(basename "$(dirname "$nuclei_file")")
                local critical_high=$(jq -r '.[] | select(.info.severity == "critical" or .info.severity == "high") | "\(.info.severity)|\(.info.name)|\(.matched_at // .host)|\(.info.description // "N/A")"' "$nuclei_file" 2>/dev/null)
                
                if [[ -n "$critical_high" ]]; then
                    echo "                <div class=\"host-section\">" >> "$REPORT_FILE"
                    echo "                    <div class=\"host-title\">🎯 $ip</div>" >> "$REPORT_FILE"
                    
                    while IFS='|' read -r severity name target description; do
                        [[ -z "$severity" ]] && continue
                        cat >> "$REPORT_FILE" << EOF
                    <div class="vulnerability $severity">
                        <div class="vuln-title"><span class="severity-$severity">$(echo $severity | tr '[:lower:]' '[:upper:]')</span> - $name</div>
                        <div class="vuln-details">
                            <strong>Target:</strong> $target<br>
                            <strong>Descrição:</strong> $(echo "$description" | cut -c1-100)...
                        </div>
                    </div>
EOF
                    done <<< "$critical_high"
                    
                    echo "                </div>" >> "$REPORT_FILE"
                fi
            fi
        done
        
        echo "            </div>" >> "$REPORT_FILE"
    fi
    
    # Adicionar seção de hosts escaneados
    cat >> "$REPORT_FILE" << EOF
            <div class="section">
                <h2>🖥️ Hosts Escaneados</h2>
                <table>
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>Portas Abertas</th>
                            <th>Vulnerabilidades</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
EOF
    
    for ip_dir in "$SCAN_RESULTS_DIR"/*; do
        if [[ -d "$ip_dir" ]]; then
            local ip=$(basename "$ip_dir")
            local nmap_file="$ip_dir/nmap.txt"
            local nuclei_file="$ip_dir/nuclei.json"
            
            local port_count=0
            local ports_list=""
            if [[ -s "$nmap_file" ]]; then
                port_count=$(grep -c "^[0-9].*open" "$nmap_file" 2>/dev/null || echo "0")
                ports_list=$(grep "^[0-9].*open" "$nmap_file" 2>/dev/null | head -5 | awk '{print $1}' | tr '\n' ' ' || echo "")
            fi
            
            local vuln_count=0
            local vuln_status="✅ Seguro"
            if [[ -s "$nuclei_file" ]]; then
                vuln_count=$(jq length "$nuclei_file" 2>/dev/null || echo "0")
                if [[ $vuln_count -gt 0 ]]; then
                    local critical_count=$(jq '[.[] | select(.info.severity == "critical")] | length' "$nuclei_file" 2>/dev/null || echo "0")
                    local high_count=$(jq '[.[] | select(.info.severity == "high")] | length' "$nuclei_file" 2>/dev/null || echo "0")
                    
                    if [[ $critical_count -gt 0 ]]; then
                        vuln_status="🚨 Crítico"
                    elif [[ $high_count -gt 0 ]]; then
                        vuln_status="⚠️ Alto Risco"
                    else
                        vuln_status="⚡ Vulnerável"
                    fi
                fi
            fi
            
            cat >> "$REPORT_FILE" << EOF
                        <tr>
                            <td><strong>$ip</strong></td>
                            <td>$port_count portas<br><small>$ports_list</small></td>
                            <td>$vuln_count vulnerabilidades</td>
                            <td>$vuln_status</td>
                        </tr>
EOF
        fi
    done
    
    # Finalizar HTML
    cat >> "$REPORT_FILE" << EOF
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>📊 Resumo de Portas Mais Comuns</h2>
EOF
    
    if [[ -f "$MASSCAN_DIR/ports_summary.txt" ]]; then
        echo "                <table>" >> "$REPORT_FILE"
        echo "                    <thead><tr><th>Porta/Protocolo</th><th>Hosts</th></tr></thead>" >> "$REPORT_FILE"
        echo "                    <tbody>" >> "$REPORT_FILE"
        
        tail -n +5 "$MASSCAN_DIR/ports_summary.txt" 2>/dev/null | head -10 | while IFS= read -r line; do
            if [[ -n "$line" && ! "$line" =~ ^# ]]; then
                local count=$(echo "$line" | awk '{print $1}')
                local port=$(echo "$line" | awk '{print $2}')
                echo "                        <tr><td><strong>$port</strong></td><td>$count hosts</td></tr>" >> "$REPORT_FILE"
            fi
        done
        
        echo "                    </tbody>" >> "$REPORT_FILE"
        echo "                </table>" >> "$REPORT_FILE"
    fi
    
    cat >> "$REPORT_FILE" << EOF
            </div>
        </div>
        
        <div class="footer">
            <p>Relatório gerado por <strong>IzysScan v1.0</strong> | 
            Ferramentas: Masscan, Nmap, Nuclei | 
            $(date '+%d/%m/%Y %H:%M:%S')</p>
        </div>
    </div>
</body>
</html>
EOF
}

# Script principal
log "[INFO] Coletando estatísticas..."
stats=$(collect_stats)

log "[INFO] Gerando relatório JSON..."
generate_json_report "$stats"

log "[INFO] Gerando relatório HTML..."
generate_html_report "$stats"

# Gerar relatório resumido em texto
SUMMARY_REPORT="$REPORT_DIR/scan_summary_$TIMESTAMP.txt"
IFS='|' read -r total_ips scanned_ips total_vulns critical_vulns high_vulns medium_vulns low_vulns open_ports <<< "$stats"

cat > "$SUMMARY_REPORT" << EOF
===============================================
         IZYSSCAN SECURITY REPORT SUMMARY
===============================================
Data do Scan: $(date '+%d/%m/%Y %H:%M:%S')
Gerado por: IzysScan v1.0

ESTATÍSTICAS GERAIS:
- IPs Descobertos: $total_ips
- IPs Escaneados: $scanned_ips  
- Portas Abertas Total: $open_ports
- Vulnerabilidades Total: $total_vulns

DISTRIBUIÇÃO DE SEVERIDADE:
- Críticas: $critical_vulns
- Altas: $high_vulns  
- Médias: $medium_vulns
- Baixas: $low_vulns

ARQUIVOS GERADOS:
- Relatório HTML: $REPORT_FILE
- Relatório JSON: $JSON_REPORT
- Resumo TXT: $SUMMARY_REPORT

DIRETÓRIOS:
- Resultados Masscan: $MASSCAN_DIR
- Resultados Detalhados: $SCAN_RESULTS_DIR
- Relatórios: $REPORT_DIR

===============================================
EOF

# Mostrar resumo no terminal
echo
echo "📋 RESUMO DO SCAN:"
echo "├── 🎯 IPs descobertos: $total_ips"
echo "├── 🔍 IPs escaneados: $scanned_ips"
echo "├── 🔌 Portas abertas: $open_ports"
echo "└── 🚨 Vulnerabilidades: $total_vulns"
echo
if [[ $total_vulns -gt 0 ]]; then
    echo "⚠️  DISTRIBUIÇÃO DE SEVERIDADE:"
    echo "├── 🚨 Críticas: $critical_vulns"
    echo "├── ⚠️  Altas: $high_vulns"
    echo "├── ⚡ Médias: $medium_vulns"
    echo "└── ℹ️  Baixas: $low_vulns"
    echo
fi

log "[SUCCESS] Relatórios gerados com sucesso!"
log "[INFO] 📄 Relatório HTML: $REPORT_FILE"
log "[INFO] 📄 Relatório JSON: $JSON_REPORT"  
log "[INFO] 📄 Resumo TXT: $SUMMARY_REPORT"

# Tentar abrir o relatório HTML no navegador (se disponível)
if command -v xdg-open &>/dev/null; then
    log "[INFO] Tentando abrir relatório no navegador..."
    xdg-open "$REPORT_FILE" 2>/dev/null &
elif command -v open &>/dev/null; then
    log "[INFO] Tentando abrir relatório no navegador..."
    open "$REPORT_FILE" 2>/dev/null &
fi