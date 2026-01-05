#!/usr/bin/env python3
"""
Script para obter informações de SSID e AP BSSID das interfaces WiFi
usando o comando netsh wlan show interfaces do Windows.
"""

import subprocess
import re
import sys


def get_wifi_interfaces():
    """
    Executa o comando 'netsh wlan show interfaces' e retorna a saída.
    
    Returns:
        str: Saída do comando ou None em caso de erro
    """
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'interfaces'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        if result.returncode != 0:
            print(f"Erro ao executar comando: {result.stderr}", file=sys.stderr)
            return None
            
        return result.stdout
    except Exception as e:
        print(f"Erro ao executar comando: {e}", file=sys.stderr)
        return None


def parse_wifi_info(output):
    """
    Parseia a saída do comando netsh para extrair SSID e AP BSSID.
    
    Args:
        output (str): Saída do comando netsh wlan show interfaces
        
    Returns:
        list: Lista de dicionários com informações de cada interface WiFi
    """
    if not output:
        return []
    
    interfaces = []
    current_interface = {}
    
    # Padrões para extrair informações (suporta português e inglês)
    # Padrão para Nome/Name: aceita "Nome" ou "Name" seguido de dois pontos
    name_pattern = re.compile(r'(?:Nome|Name)\s*:\s*(.+)', re.IGNORECASE)
    # Padrão para SSID
    ssid_pattern = re.compile(r'SSID\s*:\s*(.+)', re.IGNORECASE)
    # Padrão para AP BSSID (procura especificamente por "AP BSSID")
    ap_bssid_pattern = re.compile(r'AP\s+BSSID\s*:\s*(.+)', re.IGNORECASE)
    
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Detecta início de uma nova interface (Nome ou Name)
        if re.match(r'^(?:Nome|Name)\s*:', line, re.IGNORECASE):
            # Se já temos uma interface anterior, adiciona à lista
            if current_interface:
                interfaces.append(current_interface)
            current_interface = {}
            
            # Extrai o nome da interface
            match = name_pattern.match(line)
            if match:
                current_interface['Name'] = match.group(1).strip()
        
        # Extrai SSID (apenas se não for parte de "AP BSSID")
        elif re.search(r'^SSID\s*:', line, re.IGNORECASE) and 'AP BSSID' not in line:
            match = ssid_pattern.match(line)
            if match:
                current_interface['SSID'] = match.group(1).strip()
        
        # Extrai AP BSSID (procura especificamente por "AP BSSID")
        elif re.search(r'AP\s+BSSID\s*:', line, re.IGNORECASE):
            match = ap_bssid_pattern.match(line)
            if match:
                current_interface['AP BSSID'] = match.group(1).strip()
    
    # Adiciona a última interface se existir
    if current_interface:
        interfaces.append(current_interface)
    
    return interfaces


def main():
    """
    Função principal que executa o comando e exibe os resultados.
    """
    print("Obtendo informações das interfaces WiFi...\n")
    
    # Executa o comando
    output = get_wifi_interfaces()
    
    if output is None:
        print("Não foi possível obter informações das interfaces WiFi.")
        sys.exit(1)
    
    # Parseia a saída
    interfaces = parse_wifi_info(output)
    
    if not interfaces:
        print("Nenhuma interface WiFi encontrada ou não conectada.")
        print("\nSaída completa do comando:")
        print(output)
        sys.exit(0)
    
    # Exibe os resultados
    print("=" * 60)
    for i, interface in enumerate(interfaces, 1):
        print(f"\nInterface {i}:")
        print("-" * 60)
        
        name = interface.get('Name', 'N/A')
        ssid = interface.get('SSID', 'N/A')
        bssid = interface.get('AP BSSID', 'N/A')
        
        print(f"Nome:     {name}")
        print(f"SSID:     {ssid}")
        print(f"AP BSSID: {bssid}")
    
    print("\n" + "=" * 60)
    
    # Retorna os dados como dicionário para uso programático
    return interfaces


if __name__ == "__main__":
    main()

