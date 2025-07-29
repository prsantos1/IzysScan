#!/usr/bin/env bash
set -Eeuo pipefail

# Carregar configurações
if [[ -f .env ]]; then
    source .env
fi

if [[ -f config/default.conf ]]; then
    source config/default.conf
fi

# Função de log melhorada
log() { 
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$(basename "$0")] $*" >&2
}

# Função para validar input
validate_input() {
    local target="$1"
    local ports="$2"
    local rate="$3"
    
    # Validar target
    if [[ -f "$target" ]]; then
        log "[INFO] Usando arquivo de hosts: $target"
        # Verificar se arquivo não está vazio
        if [[ ! -s "$target" ]]; then
            log "[ERROR] Arquivo de hosts está vazio: $target"
            return 1
        fi
    elif [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
        log "[INFO] Usando range CIDR: $target"
    elif [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "[INFO] Usando range IP: $target"
    else
        log "[ERROR] Target inválido. Use CIDR (ex: 192.168.1.0/24), range (192.168.1.1-192.168.1.254) ou arquivo"
        return 1
    fi
    
    # Validar portas
    if [[ ! "$ports" =~ ^[0-9]+-[0-9]+$|^[0-9]+(,[0-9]+)*$ ]]; then
        log "[WARN] Formato de porta pode estar incorreto: $ports"
    fi
    
    # Validar rate
    if [[ ! "$rate" =~ ^[0-9]+$ ]] || [[ "$rate" -lt 100 ]] || [[ "$rate" -gt ${MAX_RATE:-100000} ]]; then
        log "[WARN] Rate fora do range recomendado (100-${MAX_RATE:-100000}): $rate"
    fi
    
    return 0
}

# Função para cleanup em caso de erro
cleanup() {
    log "[INFO] Limpando containers em execução..."
    docker compose down --remove-orphans 2>/dev/null || true
}

# Função para mostrar estatísticas
show_stats() {
    log "[INFO] ===== Estatísticas Finais ====="
    
    if [[ -f outputs/masscan/ips.txt ]]; then
        local ip_count=$(wc -l < outputs/masscan/ips.txt)
        log "[INFO] IPs ativos encontrados: $ip_count"
    fi
    
    local result_files=$(find outputs/scan_results -name "*.xml" -o -name "*.json" -o -name "*.txt" 2>/dev/null | wc -l)
    log "[INFO] Arquivos de resultado gerados: $result_files"
    
    local scan_dirs=$(find outputs/scan_results -type d -mindepth 1 2>/dev/null | wc -l)
    log "[INFO] IPs escaneados detalhadamente: $scan_dirs"
    
    log "[INFO] Resultados disponíveis em: outputs/"
}

# Trap para cleanup
trap cleanup EXIT

# Banner
echo "╔════════════════════════════════════════╗"
echo "║            IzysScan Pipeline           ║"
echo "║        Security Scanning Suite         ║"
echo "╚════════════════════════════════════════╝"
echo

log "[INFO] ===== Iniciando IzysScan Pipeline ====="

# Verificar dependências
log "[SETUP] Verificando dependências..."
if [[ -x scripts/setup_deps.sh ]]; then
    ./scripts/setup_deps.sh
else
    log "[WARN] setup_deps.sh não encontrado ou não executável"
fi

log "[SETUP] Verificando permissões..."  
if [[ -x scripts/check_perms.sh ]]; then
    ./scripts/check_perms.sh
else
    log "[ERROR] check_perms.sh não encontrado ou não executável"
    exit 1
fi

# Verificar se Docker está funcionando
if ! docker compose version &>/dev/null; then
    log "[ERROR] Docker Compose não está funcionando"
    exit 1
fi

# Input interativo com validação
while true; do
    echo
    echo "📋 Configuração do Scan:"
    echo "   Portas padrão: ${DEFAULT_PORTS:-1-1000}"
    echo "   Rate padrão: ${DEFAULT_RATE:-1000}"
    echo
    
    read -rp "📍 Digite faixa de IPs (ex: 192.168.0.0/24) ou caminho para arquivo: " TARGET
    read -rp "🔌 Digite range de portas (ENTER para padrão: ${DEFAULT_PORTS:-1-1000}): " PORTS
    read -rp "⚡ Digite taxa do Masscan (ENTER para padrão: ${DEFAULT_RATE:-1000}): " RATE
    
    # Usar valores padrão se não informados
    PORTS=${PORTS:-${DEFAULT_PORTS:-1-1000}}
    RATE=${RATE:-${DEFAULT_RATE:-1000}}
    
    if validate_input "$TARGET" "$PORTS" "$RATE"; then
        break
    else
        echo "❌ Input inválido. Tente novamente."
    fi
done

log "[INPUT] TARGET='$TARGET', PORTS='$PORTS', RATE='$RATE'"

# Criar diretórios
mkdir -p outputs/{masscan,scan_results}

# Fase 1: Masscan
log "[1/4] 🔍 Iniciando Masscan discovery..."
echo "📊 Target: $TARGET | Ports: $PORTS | Rate: $RATE"

# Preparar argumentos do masscan
if [[ -f "$TARGET" ]]; then
    # Copiar arquivo para o volume do container
    cp "$TARGET" "outputs/masscan/hosts.txt"
    MASSCAN_CMD="docker compose run --rm masscan -iL /data/hosts.txt -p$PORTS --rate $RATE -oJ -"
else
    MASSCAN_CMD="docker compose run --rm masscan $TARGET -p$PORTS --rate $RATE -oJ -"
fi

# Executar masscan com timeout
log "[INFO] Executando: $MASSCAN_CMD"
start_time=$(date +%s)

if timeout "${SCAN_TIMEOUT:-3600}" $MASSCAN_CMD > outputs/masscan/masscan.json 2>&1; then
    end_time=$(date +%s)
    elapsed=$((end_time - start_time))
    log "[OK] Masscan concluído em ${elapsed}s"
else
    exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
        log "[ERROR] Masscan timeout após ${SCAN_TIMEOUT:-3600}s"
    else
        log "[ERROR] Masscan falhou com código: $exit_code"
    fi
    exit 1
fi

# Verificar se gerou resultados válidos
if [[ ! -s outputs/masscan/masscan.json ]]; then
    log "[ERROR] Masscan não gerou resultados"
    exit 1
fi

# Validar JSON
if ! jq empty outputs/masscan/masscan.json 2>/dev/null; then
    log "[ERROR] Resultado do Masscan não é um JSON válido"
    exit 1
fi

# Fase 2: Extração de IPs
log "[2/4] 📝 Extraindo IPs ativos..."
if [[ -x scripts/extract_ips.sh ]]; then
    ./scripts/extract_ips.sh
else
    log "[WARN] extract_ips.sh não encontrado, extraindo IPs manualmente..."
    jq -r '.[] | select(.open) | .ip' outputs/masscan/masscan.json | sort -u > outputs/masscan/ips.txt
fi

# Verificar se há IPs para continuar
if [[ ! -s outputs/masscan/ips.txt ]]; then
    log "[WARN] Nenhum IP ativo encontrado. Pipeline finalizado."
    show_stats
    exit 0
fi

ip_count=$(wc -l < outputs/masscan/ips.txt)
log "[INFO] Encontrados $ip_count IPs ativos para varredura detalhada"

# Mostrar primeiros IPs encontrados
log "[INFO] Primeiros IPs encontrados:"
head -5 outputs/masscan/ips.txt | while read -r ip; do
    log "  - $ip"
done
[[ $ip_count -gt 5 ]] && log "  ... e mais $((ip_count - 5)) IPs"

# Fase 3: Scanning detalhado
log "[3/4] 🎯 Iniciando varreduras detalhadas..."
echo "🔄 Processando $ip_count IPs com Nmap e Nuclei..."

if [[ -x scripts/run_per_host.sh ]]; then
    ./scripts/run_per_host.sh
else
    log "[ERROR] run_per_host.sh não encontrado ou não executável"
    exit 1
fi

# Fase 4: Relatório final
log "[4/4] 📊 Gerando relatório final..."
if [[ -x scripts/generate_report.sh ]]; then
    ./scripts/generate_report.sh
else
    log "[INFO] Script de relatório não encontrado, pulando..."
fi

# Mostrar estatísticas finais
show_stats

echo
echo "✅ Pipeline IzysScan concluído com sucesso!"
echo "📁 Verifique os resultados em: outputs/"
echo

log "[SUCCESS] ===== Pipeline Completo ====="