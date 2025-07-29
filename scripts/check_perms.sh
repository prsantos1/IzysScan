#!/usr/bin/env bash
set -Eeuo pipefail

# Função de log melhorada
log() { 
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$(basename "$0")] $*" >&2
}

# Carregar configurações do .env se existir
if [[ -f .env ]]; then
    source .env
fi

# Variáveis
CURRENT_UID=${UID:-$(id -u)}
CURRENT_GID=${GID:-$(id -g)}
DIRS=("outputs/masscan" "outputs/scan_results" "config" "scripts")

log "[INFO] Verificando permissões para UID:$CURRENT_UID GID:$CURRENT_GID"

# Criar diretórios base se não existirem
for dir in "${DIRS[@]}"; do
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        log "[INFO] Criado diretório: $dir"
    fi
done

# Verificar e ajustar permissões
for dir in "${DIRS[@]}"; do
    # Verificar ownership atual
    if [[ -d "$dir" ]]; then
        current_owner=$(stat -c '%u:%g' "$dir")
        expected_owner="$CURRENT_UID:$CURRENT_GID"
        
        if [[ "$current_owner" != "0:0" ]] && [[ "$current_owner" != "$expected_owner" ]]; then
            log "[WARN] $dir possui owner $current_owner, ajustando para $expected_owner"
            
            # Verificar se precisa de sudo
            if [[ $EUID -ne 0 ]] && [[ ! -w "$dir" ]]; then
                sudo chown -R "$expected_owner" "$dir"
            else
                chown -R "$expected_owner" "$dir" 2>/dev/null || sudo chown -R "$expected_owner" "$dir"
            fi
        fi
        
        # Definir permissões apropriadas
        case "$dir" in
            "scripts")
                # Scripts precisam ser executáveis
                chmod -R u+rwx,g+rx,o+rx "$dir" 2>/dev/null || {
                    log "[WARN] Falha ao definir permissões em $dir, tentando com sudo"
                    sudo chmod -R u+rwx,g+rx,o+rx "$dir"
                }
                ;;
            *)
                # Outros diretórios apenas leitura/escrita
                chmod -R u+rwX,g+rX "$dir" 2>/dev/null || {
                    log "[WARN] Falha ao definir permissões em $dir, tentando com sudo"
                    sudo chmod -R u+rwX,g+rX "$dir"
                }
                ;;
        esac
        
        # Verificar resultado
        final_perms=$(stat -c '%a %u:%g' "$dir")
        log "[OK] Permissões ajustadas: $dir ($final_perms)"
    fi
done

# Verificar scripts específicos
SCRIPTS=("setup_deps.sh" "check_perms.sh" "run_full_scan.sh" "extract_ips.sh" "run_per_host.sh" "generate_report.sh")

log "[INFO] Verificando scripts executáveis..."
for script in "${SCRIPTS[@]}"; do
    script_path="scripts/$script"
    if [[ -f "$script_path" ]]; then
        if [[ ! -x "$script_path" ]]; then
            log "[WARN] $script_path não é executável, corrigindo..."
            chmod +x "$script_path" 2>/dev/null || sudo chmod +x "$script_path"
        fi
        log "[OK] $script_path é executável"
    else
        log "[WARN] $script_path não encontrado"
    fi
done

# Verificar arquivos de configuração
CONFIG_FILES=(".env" "docker-compose.yml" "Makefile")

log "[INFO] Verificando arquivos de configuração..."
for config_file in "${CONFIG_FILES[@]}"; do
    if [[ -f "$config_file" ]]; then
        if [[ ! -r "$config_file" ]]; then
            log "[WARN] $config_file não é legível, corrigindo..."
            chmod u+r "$config_file" 2>/dev/null || sudo chmod u+r "$config_file"
        fi
        log "[OK] $config_file é legível"
    else
        log "[WARN] $config_file não encontrado"
    fi
done

# Verificar se o usuário está no grupo docker (se não for root)
if [[ $EUID -ne 0 ]]; then
    if ! groups | grep -q docker; then
        log "[WARN] Usuário $(whoami) não está no grupo docker"
        log "[INFO] Execute: sudo usermod -aG docker $(whoami)"
        log "[INFO] Depois faça logout/login ou execute: newgrp docker"
    else
        log "[OK] Usuário está no grupo docker"
    fi
fi

# Teste de escrita nos diretórios de output
log "[INFO] Testando permissões de escrita..."
for dir in "outputs/masscan" "outputs/scan_results"; do
    test_file="$dir/.write_test"
    if echo "test" > "$test_file" 2>/dev/null; then
        rm -f "$test_file"
        log "[OK] Escrita OK em $dir"
    else
        log "[ERROR] Sem permissão de escrita em $dir"
        exit 1
    fi
done

log "[SUCCESS] ✅ Verificação de permissões concluída com sucesso!"