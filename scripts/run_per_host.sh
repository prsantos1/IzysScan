#!/usr/bin/env bash
set -Eeuo pipefail

# Carregar configurações
if [[ -f .env ]]; then
    source .env
fi

if [[ -f config/default.conf ]]; then
    source config/default.conf  
fi

# Configurações padrão
MAX_PARALLEL_JOBS=${MAX_PARALLEL_JOBS:-3}
NMAP_TIMEOUT=${NMAP_TIMEOUT:-300}
NUCLEI_TIMEOUT=${NUCLEI_TIMEOUT:-180}
NMAP_SCRIPTS=${NMAP_SCRIPTS:-"vulners,vulscan"}
NUCLEI_SEVERITY=${NUCLEI_SEVERITY:-"critical,high,medium"}
NUCLEI_RATE_LIMIT=${NUCLEI_RATE_LIMIT:-10}
NUCLEI_BULK_SIZE=${NUCLEI_BULK_SIZE:-25}

log() { 
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$(basename "$0")] $*" >&2
}

# Função para processar um IP
process_ip() {
    local ip="$1"
    local host_dir="outputs/scan_results/$ip"
    local current_job="$2"
    local total_jobs="$3"
    
    log "[START] ($current_job/$total_jobs) Processando $ip"
    mkdir -p "$host_dir"
    
    # Nmap com timeout e melhor logging
    (
        log "[$ip][nmap] Iniciando scan de vulnerabilidades..."
        local nmap_start=$(date +%s)
        
        timeout "$NMAP_TIMEOUT" docker compose run --rm \
            -v "$(pwd)/$host_dir":/data nmap \
            -sS -sV -sC "$ip" \
            --script "$NMAP_SCRIPTS" \
            --script-args vulscan.vulscandb=scipag_vulscandb \
            -oN /data/nmap.txt -oX /data/nmap.xml -oG /data/nmap.gnmap \
            --stats-every 30s \
            2>&1 | while IFS= read -r line; do 
                echo "$(date '+%H:%M:%S') [$ip][nmap] $line"
            done
        
        local nmap_exit=${PIPESTATUS[0]}
        local nmap_end=$(date +%s)
        local nmap_duration=$((nmap_end - nmap_start))
        
        if [[ $nmap_exit -eq 124 ]]; then
            log "[$ip][nmap] ⏰ TIMEOUT após ${NMAP_TIMEOUT}s"
            echo "SCAN TIMEOUT após ${NMAP_TIMEOUT}s" >> "$host_dir/nmap.txt"
        elif [[ $nmap_exit -eq 0 ]]; then
            log "[$ip][nmap] ✅ Concluído em ${nmap_duration}s"
        else
            log "[$ip][nmap] ❌ Erro (código: $nmap_exit) após ${nmap_duration}s"
        fi
    ) &
    local nmap_pid=$!
    
    # Nuclei com timeout e configurações otimizadas
    (
        log "[$ip][nuclei] Iniciando scan de vulnerabilidades..."
        local nuclei_start=$(date +%s)
        
        # Tentar tanto HTTP quanto HTTPS
        timeout "$NUCLEI_TIMEOUT" docker compose run --rm \
            -v "$(pwd)/$host_dir":/data nuclei \
            -target "http://$ip" -target "https://$ip" \
            -severity "$NUCLEI_SEVERITY" \
            -o /data/nuclei.txt -json -o /data/nuclei.json \
            -rate-limit "$NUCLEI_RATE_LIMIT" -bulk-size "$NUCLEI_BULK_SIZE" \
            -update-templates -stats -silent \
            2>&1 | while IFS= read -r line; do 
                echo "$(date '+%H:%M:%S') [$ip][nuclei] $line"
            done
            
        local nuclei_exit=${PIPESTATUS[0]}
        local nuclei_end=$(date +%s)
        local nuclei_duration=$((nuclei_end - nuclei_start))
        
        if [[ $nuclei_exit -eq 124 ]]; then
            log "[$ip][nuclei] ⏰ TIMEOUT após ${NUCLEI_TIMEOUT}s"
            echo "SCAN TIMEOUT após ${NUCLEI_TIMEOUT}s" >> "$host_dir/nuclei.txt"
        elif [[ $nuclei_exit -eq 0 ]]; then
            log "[$ip][nuclei] ✅ Concluído em ${nuclei_duration}s"
        else
            log "[$ip][nuclei] ❌ Erro (código: $nuclei_exit) após ${nuclei_duration}s"
        fi
    ) &
    local nuclei_pid=$!
    
    # Aguardar ambos os processos
    wait $nmap_pid $nuclei_pid
    
    # Verificar e contar resultados
    local findings=0
    local vulns_found=0
    
    # Contar findings do Nmap
    if [[ -s "$host_dir/nmap.txt" ]]; then
        findings=$((findings + 1))
        # Contar vulnerabilidades específicas
        local nmap_vulns=$(grep -c "VULNERABLE\|CVE-\|vuln" "$host_dir/nmap.txt" 2>/dev/null || echo "0")
        vulns_found=$((vulns_found + nmap_vulns))
    fi
    
    # Contar findings do Nuclei
    if [[ -s "$host_dir/nuclei.json" ]]; then
        findings=$((findings + 1))
        # Contar vulnerabilidades do Nuclei
        local nuclei_vulns=$(jq length "$host_dir/nuclei.json" 2>/dev/null || echo "0")
        vulns_found=$((vulns_found + nuclei_vulns))
    fi
    
    # Gerar resumo por host
    {
        echo "=== Resumo do Scan - $ip ==="
        echo "Data: $(date)"
        echo "Ferramentas: Nmap, Nuclei"
        echo
        echo "Arquivos gerados: $findings"
        echo "Vulnerabilidades encontradas: $vulns_found"
        echo
        if [[ -s "$host_dir/nmap.txt" ]]; then
            echo "=== Portas Abertas (Nmap) ==="
            grep "^[0-9].*open" "$host_dir/nmap.txt" 2>/dev/null || echo "Nenhuma porta encontrada"
            echo
        fi
        if [[ -s "$host_dir/nuclei.json" && $nuclei_vulns -gt 0 ]]; then
            echo "=== Vulnerabilidades Nuclei ==="
            jq -r '.[] | "\(.info.severity | ascii_upcase): \(.info.name)"' "$host_dir/nuclei.json" 2>/dev/null | sort | head -10
            [[ $nuclei_vulns -gt 10 ]] && echo "... e mais $((nuclei_vulns - 10)) vulnerabilidades"
            echo
        fi
    } > "$host_dir/scan_summary.txt"
    
    if [[ $vulns_found -gt 0 ]]; then
        log "[DONE] ($current_job/$total_jobs) $ip - 🚨 $vulns_found vulnerabilidade(s) encontrada(s)"
    else
        log "[DONE] ($current_job/$total_jobs) $ip - ✅ Scan concluído (sem vulnerabilidades)"
    fi
}

# Script principal
IPS_FILE="outputs/masscan/ips.txt"

# Verificações iniciais
[[ ! -f "$IPS_FILE" ]] && { 
    log "[ERROR] Arquivo não encontrado: $IPS_FILE"
    exit 1
}

[[ ! -s "$IPS_FILE" ]] && {
    log "[WARN] Arquivo vazio: $IPS_FILE"
    exit 0
}

total_ips=$(wc -l < "$IPS_FILE")
log "[INFO] ===== Iniciando Scan Detalhado ====="
log "[INFO] Processando $total_ips IPs com máximo de $MAX_PARALLEL_JOBS jobs paralelos"
log "[INFO] Timeouts: Nmap=${NMAP_TIMEOUT}s, Nuclei=${NUCLEI_TIMEOUT}s"

# Contador para controle de jobs paralelos
job_count=0
processed=0
failed=0

# Array para armazenar PIDs dos jobs
declare -a job_pids=()

while IFS= read -r IP || [[ -n "$IP" ]]; do
    # Remover espaços em branco
    IP=$(echo "$IP" | tr -d '[:space:]')
    [[ -z "$IP" ]] && continue
    
    # Validar IP
    if [[ ! "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log "[WARN] IP inválido ignorado: '$IP'"
        continue
    fi
    
    # Controle de paralelismo
    if [[ $job_count -ge $MAX_PARALLEL_JOBS ]]; then
        # Aguardar qualquer job terminar
        wait -n
        job_count=$((job_count - 1))
    fi
    
    # Iniciar processamento em background
    processed=$((processed + 1))
    process_ip "$IP" "$processed" "$total_ips" &
    job_pids+=($!)
    job_count=$((job_count + 1))
    
    log "[PROGRESS] $processed/$total_ips IPs iniciados ($job_count jobs ativos)"
    
done < "$IPS_FILE"

# Aguardar jobs restantes
log "[INFO] Aguardando conclusão dos últimos $job_count jobs..."
for pid in "${job_pids[@]}"; do
    if wait "$pid"; then
        : # Job success
    else
        failed=$((failed + 1))
    fi
done

# Estatísticas finais
successful=$((processed - failed))
log "[SUCCESS] ===== Scan Detalhado Concluído ====="
log "[STATS] IPs processados: $processed"
log "[STATS] Sucessos: $successful"
log "[STATS] Falhas: $failed"

# Contar arquivos gerados
nmap_files=$(find outputs/scan_results -name "nmap.xml" 2>/dev/null | wc -l)
nuclei_files=$(find outputs/scan_results -name "nuclei.json" -size +0c 2>/dev/null | wc -l)
log "[STATS] Arquivos Nmap gerados: $nmap_files"
log "[STATS] Arquivos Nuclei com conteúdo: $nuclei_files"

# Contar vulnerabilidades totais
total_vulns=0
if command -v jq &>/dev/null; then
    for nuclei_file in outputs/scan_results/*/nuclei.json; do
        if [[ -s "$nuclei_file" ]]; then
            vulns=$(jq length "$nuclei_file" 2>/dev/null || echo "0")
            total_vulns=$((total_vulns + vulns))
        fi
    done
fi

if [[ $total_vulns -gt 0 ]]; then
    log "[ALERT] 🚨 Total de vulnerabilidades encontradas: $total_vulns"
else
    log "[INFO] ✅ Nenhuma vulnerabilidade crítica detectada"
fi

log "[INFO] Resultados disponíveis em: outputs/scan_results/"

if [[ $failed -gt 0 ]]; then
    log "[WARN] $failed jobs falharam. Verifique os logs acima para detalhes."
    exit 1
fi