FROM alpine:3.18

LABEL maintainer="izysScan@security.local"
LABEL description="Nmap with vulnerability scanning scripts"

# Instalar dependências
RUN apk add --no-cache nmap nmap-scripts nmap-nselibs git jq curl

# Instalar scripts de vulnerabilidade com retry
RUN for i in 1 2 3; do \
      rm -rf /usr/share/nmap/scripts/vulners /opt/vulscan 2>/dev/null || true && \
      git clone --depth 1 https://github.com/vulnersCom/nmap-vulners.git /usr/share/nmap/scripts/vulners \
      && git clone --depth 1 https://github.com/scipag/vulscan.git /opt/vulscan && break \
      || (echo "Retry $i cloning scripts" && sleep 5); \
    done \
 && ln -sf /opt/vulscan/vulscan.nse /usr/share/nmap/scripts/ \
 && nmap --script-updatedb

# Criar diretório de trabalho
WORKDIR /data

ENTRYPOINT ["nmap"]