#!/bin/bash

########## DEBUG Mode ##########
##                            ##
if [ -z ${INSTALLER_DEBUG+x} ]; then INSTALLER_DEBUG=0
else INSTALLER_DEBUG=1
fi
##                            ##
################################

# Airset Dependencies Auto-Installer v03 — Parrot OS 7
# By Alef Carvalho [W4R10CK] [youtube.com/c/alefcarvalhobr]
# Modificações são permitidas desde que se mantenham os créditos ao autor original.

# Config
version=3
revision=1

# Colors
white="\033[1;37m"
grey="\033[0;37m"
red="\033[1;31m"
green="\033[1;32m"
yellow="\033[1;33m"
blue="\033[1;34m"
transparent="\e[0m"

# Temp dir
rm -rf /tmp/Installer/
mkdir -p /tmp/Installer/
DUMP_PATH="/tmp/Installer/"

function conditional_clear() {
    if [[ "$INSTALLER_output_device" != "/dev/stdout" ]]; then clear; fi
}

# Debug config
if [ "$INSTALLER_DEBUG" = "1" ]; then
    export INSTALLER_output_device=/dev/stdout
    HOLD="-hold"
else
    export INSTALLER_output_device=/dev/null
    HOLD=""
fi

# Verifica root
if [[ $EUID -ne 0 ]]; then
    echo -e "\e[1;31mVocê precisa executar esse script como root.${transparent}"
    exit 1
fi

# Verifica sessão gráfica
if [ -z "${DISPLAY:-}" ]; then
    echo -e "\e[1;31mO script deve ser executado dentro de uma sessão gráfica (X11).${transparent}"
    exit 1
fi

clear

function mostrarheader() {
    echo
    echo -e "${red}                █████╗ ██╗██████╗ ███████╗███████╗████████╗ "
    echo -e "${red}               ██╔══██╗██║██╔══██╗██╔════╝██╔════╝╚══██╔══╝"
    echo -e "${red}               ███████║██║██████╔╝███████╗█████╗     ██║   "
    echo -e "${red}               ██╔══██║██║██╔══██╗╚════██║██╔══╝     ██║   "
    echo -e "${red}               ██║  ██║██║██║  ██║███████║███████╗   ██║   "
    echo -e "${red}               ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   "
    echo -e "${white}         Airset Dependencies Auto-Installer v03 | Parrot OS 7"
    echo -e "${green}  By Alef Carvalho [W4R10CK] [youtube.com/c/alefcarvalhobr] ${transparent}"
    echo
}

function setresolution() {
    function resA() { TOPLEFT="-geometry 90x13+0+0"; TOPRIGHT="-geometry 83x26-0+0"; BOTTOMLEFT="-geometry 90x24+0-0"; BOTTOMRIGHT="-geometry 75x12-0-0"; TOPLEFTBIG="-geometry 91x42+0+0"; }
    function resB() { TOPLEFT="-geometry 92x14+0+0"; TOPRIGHT="-geometry 68x25-0+0"; BOTTOMLEFT="-geometry 92x36+0-0"; BOTTOMRIGHT="-geometry 74x20-0-0"; TOPLEFTBIG="-geometry 100x52+0+0"; }
    function resC() { TOPLEFT="-geometry 100x20+0+0"; TOPRIGHT="-geometry 109x20-0+0"; BOTTOMLEFT="-geometry 100x30+0-0"; BOTTOMRIGHT="-geometry 109x20-0-0"; TOPLEFTBIG="-geometry 100x52+0+0"; }
    function resD() { TOPLEFT="-geometry 110x35+0+0"; TOPRIGHT="-geometry 99x40-0+0"; BOTTOMLEFT="-geometry 110x35+0-0"; BOTTOMRIGHT="-geometry 99x30-0-0"; TOPLEFTBIG="-geometry 110x72+0+0"; }
    function resE() { TOPLEFT="-geometry 130x43+0+0"; TOPRIGHT="-geometry 68x25-0+0"; BOTTOMLEFT="-geometry 130x40+0-0"; BOTTOMRIGHT="-geometry 132x35-0-0"; TOPLEFTBIG="-geometry 130x85+0+0"; }

    detectedresolution=$(xdpyinfo | grep -A 3 "screen #0" | grep dimensions | tr -s " " | cut -d" " -f 3)
    case $detectedresolution in
        "1024x600")  resA ;;
        "1024x768")  resB ;;
        "1280x768")  resC ;;
        "1366x768")  resC ;;
        "1280x1024") resD ;;
        "1600x1200") resE ;;
        "1920x1080") resE ;;
        *)           resA ;;
    esac
}

# ─────────────────────────────────────────────────────────────
# Função auxiliar de instalação
# Uso: install_dep "Nome exibido" "comando_de_teste" "pacote(s)"
# ─────────────────────────────────────────────────────────────
install_dep() {
    local label="$1"
    local testcmd="$2"
    local pkg="$3"

    printf "%-22s" "$label"
    if command -v "$testcmd" &>/dev/null || [ -x "$testcmd" ]; then
        echo -e "${green}OK!${transparent}"
    else
        echo -e "${yellow}Instalando...${transparent}"
        xterm $HOLD -title "Instalando $label" $TOPLEFTBIG \
            -bg "#FFFFFF" -fg "#000000" \
            -e apt-get install --yes $pkg
        # Confirma após instalação
        if command -v "$testcmd" &>/dev/null || [ -x "$testcmd" ]; then
            echo -e "  ${green}✔ $label instalado com sucesso!${transparent}"
        else
            echo -e "  ${red}✘ Falha ao instalar $label ($pkg)${transparent}"
        fi
    fi
    sleep 0.025
}

# ─────────────────────────────────────────────────────────────
# Função especial para php-cgi (nome versionado no Parrot OS 7)
# ─────────────────────────────────────────────────────────────
install_phpcgi() {
    printf "%-22s" "php-cgi"
    # Testa vários nomes possíveis
    local found=""
    for bin in php8.2-cgi php8.1-cgi php-cgi; do
        if command -v "$bin" &>/dev/null; then found="$bin"; break; fi
    done

    if [ -n "$found" ]; then
        echo -e "${green}OK! ($found)${transparent}"
    else
        echo -e "${yellow}Instalando php8.2-cgi...${transparent}"
        xterm $HOLD -title "Instalando php8.2-cgi" $TOPLEFTBIG \
            -bg "#FFFFFF" -fg "#000000" \
            -e apt-get install --yes php8.2-cgi php8.2-common
        # fallback
        for bin in php8.2-cgi php8.1-cgi php-cgi; do
            command -v "$bin" &>/dev/null && found="$bin" && break
        done
        if [ -n "$found" ]; then
            echo -e "  ${green}✔ php-cgi instalado: $found${transparent}"
        else
            echo -e "  ${red}✘ Falha ao instalar php-cgi${transparent}"
        fi
    fi
    sleep 0.025
}

# ════════════════════════════════════════════════════════════
#                        INÍCIO
# ════════════════════════════════════════════════════════════
conditional_clear
mostrarheader
setresolution

echo -e "${blue}[*]${transparent} Preparando sistema (Parrot OS 7)..."
echo

# Garante que apt está funcionando e atualiza listas
apt-get install -f -y          &>"$INSTALLER_output_device"
apt-get autoremove -y          &>"$INSTALLER_output_device"
apt-get autoclean -y           &>"$INSTALLER_output_device"
apt-get clean -y               &>"$INSTALLER_output_device"
apt-get update                 &>"$INSTALLER_output_device"

# Instala xterm primeiro (necessário para as demais janelas)
if ! command -v xterm &>/dev/null; then
    echo -e "${yellow}Instalando xterm (necessário)...${transparent}"
    apt-get install --yes xterm &>"$INSTALLER_output_device"
fi

conditional_clear
mostrarheader
echo -e "${blue}[*]${transparent} Verificando e instalando dependências...\n"

# ─── Ferramentas wireless (aircrack-ng suite) ──────────────
install_dep  "aircrack-ng"    "aircrack-ng"   "aircrack-ng"
install_dep  "aireplay-ng"    "aireplay-ng"   "aircrack-ng"
install_dep  "airmon-ng"      "airmon-ng"     "aircrack-ng"
install_dep  "airodump-ng"    "airodump-ng"   "aircrack-ng"

# ─── AP Falso ──────────────────────────────────────────────
install_dep  "hostapd"        "hostapd"       "hostapd"

# ─── Servidor Web ──────────────────────────────────────────
install_dep  "lighttpd"       "lighttpd"      "lighttpd"
install_phpcgi

# ─── DHCP ──────────────────────────────────────────────────
install_dep  "dhcpd"          "dhcpd"         "isc-dhcp-server"

# ─── Ataques WPS ───────────────────────────────────────────
install_dep  "reaver"         "reaver"        "reaver"
install_dep  "bully"          "bully"         "bully"

# ─── Flood / Deauth ────────────────────────────────────────
install_dep  "mdk3"           "mdk3"          "mdk3"

# ─── Handshake / Cracking ──────────────────────────────────
install_dep  "pyrit"          "pyrit"         "pyrit"
install_dep  "hashcat"        "hashcat"       "hashcat"

# ─── hcxtools (converte .cap → .hc22000 para hashcat) ─────
install_dep  "hcxpcapngtool"  "hcxpcapngtool" "hcxtools"
install_dep  "hcxdumptool"    "hcxdumptool"   "hcxdumptool"

# ─── Rede / Sistema ────────────────────────────────────────
install_dep  "iwconfig"       "iwconfig"      "wireless-tools"
install_dep  "macchanger"     "macchanger"    "macchanger"
install_dep  "nmap"           "nmap"          "nmap"
install_dep  "rfkill"         "rfkill"        "rfkill"
install_dep  "curl"           "curl"          "curl"
install_dep  "openssl"        "openssl"       "openssl"

# ─── Python 3 (Python 2 foi removido do Parrot OS 7) ──────
install_dep  "python3"        "python3"       "python3"

# ─── Utilitários ───────────────────────────────────────────
install_dep  "unzip"          "unzip"         "unzip"
install_dep  "awk"            "awk"           "gawk"
install_dep  "xterm"          "xterm"         "xterm"
install_dep  "zenity"         "zenity"        "zenity"
install_dep  "strings"        "strings"       "binutils"
install_dep  "fuser"          "fuser"         "psmisc"

# ════════════════════════════════════════════════════════════
# Verificação final
# ════════════════════════════════════════════════════════════
echo
echo -e "${blue}[*]${transparent} Verificação final..."
echo

FALHAS=0
check_final() {
    local label="$1"
    local cmd="$2"
    printf "  %-22s" "$label"
    if command -v "$cmd" &>/dev/null || [ -x "$cmd" ]; then
        echo -e "${green}✔ OK${transparent}"
    else
        echo -e "${red}✘ Não encontrado${transparent}"
        FALHAS=$((FALHAS + 1))
    fi
}

check_final "aircrack-ng"    "aircrack-ng"
check_final "aireplay-ng"    "aireplay-ng"
check_final "airmon-ng"      "airmon-ng"
check_final "airodump-ng"    "airodump-ng"
check_final "hostapd"        "hostapd"
check_final "lighttpd"       "lighttpd"
check_final "dhcpd"          "dhcpd"
check_final "reaver"         "reaver"
check_final "bully"          "bully"
check_final "mdk3"           "mdk3"
check_final "pyrit"          "pyrit"
check_final "hashcat"        "hashcat"
check_final "hcxpcapngtool"  "hcxpcapngtool"
check_final "iwconfig"       "iwconfig"
check_final "macchanger"     "macchanger"
check_final "nmap"           "nmap"
check_final "rfkill"         "rfkill"
check_final "curl"           "curl"
check_final "python3"        "python3"
check_final "unzip"          "unzip"
check_final "zenity"         "zenity"
check_final "strings"        "strings"
check_final "fuser"          "fuser"

# php-cgi — verificação especial
printf "  %-22s" "php-cgi"
PHP_FOUND=""
for bin in php8.2-cgi php8.1-cgi php-cgi; do
    command -v "$bin" &>/dev/null && PHP_FOUND="$bin" && break
done
if [ -n "$PHP_FOUND" ]; then
    echo -e "${green}✔ OK ($PHP_FOUND)${transparent}"
else
    echo -e "${red}✘ Não encontrado${transparent}"
    FALHAS=$((FALHAS + 1))
fi

echo
if [ "$FALHAS" -eq 0 ]; then
    echo -e "${green}[✔] Todas as dependências instaladas com sucesso!${transparent}"
    echo -e "${green}    Você já pode executar o airset.${transparent}"
else
    echo -e "${yellow}[!] $FALHAS dependência(s) com problema. Verifique acima e instale manualmente.${transparent}"
    echo -e "${yellow}    Comando rápido:${transparent}"
    echo -e "${white}    apt-get install aircrack-ng hostapd lighttpd isc-dhcp-server macchanger mdk3"
    echo -e "    reaver bully php8.2-cgi nmap pyrit rfkill binutils psmisc xterm zenity"
    echo -e "    curl unzip hcxtools hcxdumptool hashcat wireless-tools python3 gawk${transparent}"
fi

echo
sleep 2
