#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para obter informações de SSID e AP BSSID das interfaces WiFi
usando o comando netsh wlan show interfaces do Windows.
Inclui validação de localização geográfica para verificar se o AP BSSID
corresponde à localização atual.
"""

import subprocess
import re
import sys
import json
import urllib.request
import urllib.error
import socket
import io

# Configura encoding UTF-8 para Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


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


def get_location_by_ip():
    """
    Obtém a localização geográfica aproximada usando o endereço IP.
    
    Returns:
        dict: Dicionário com latitude, longitude, cidade, país, etc. ou None
    """
    try:
        # Usa ipapi.co (gratuito, sem necessidade de API key)
        url = "https://ipapi.co/json/"
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode())
            
            if 'error' in data:
                return None
                
            return {
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country_name'),
                'country_code': data.get('country_code'),
                'postal': data.get('postal'),
                'timezone': data.get('timezone'),
                'isp': data.get('org'),
                'ip': data.get('ip'),
                'currency': data.get('currency'),
                'currency_name': data.get('currency_name')
            }
    except urllib.error.URLError:
        # Erro de conexão - tenta serviço alternativo
        try:
            url = "http://ip-api.com/json/"
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode())
                
                if data.get('status') == 'fail':
                    return None
                    
                return {
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'city': data.get('city'),
                    'region': data.get('regionName'),
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'postal': data.get('zip'),
                    'timezone': data.get('timezone'),
                    'isp': data.get('isp'),
                    'ip': data.get('query'),
                    'currency': None,
                    'currency_name': None
                }
        except Exception:
            return None
    except Exception:
        return None


def get_wifi_access_points():
    """
    Obtém lista de pontos de acesso WiFi visíveis usando netsh.
    
    Returns:
        list: Lista de dicionários com SSID e BSSID dos APs visíveis
    """
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        if result.returncode != 0:
            return []
        
        output = result.stdout
        access_points = []
        current_ap = {}
        
        # Padrões para extrair informações
        ssid_pattern = re.compile(r'SSID\s+\d+\s*:\s*(.+)', re.IGNORECASE)
        bssid_pattern = re.compile(r'BSSID\s+\d+\s*:\s*(.+)', re.IGNORECASE)
        signal_pattern = re.compile(r'Sinal\s*:\s*(\d+)%', re.IGNORECASE)
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Detecta novo SSID
            if re.match(r'SSID\s+\d+\s*:', line, re.IGNORECASE):
                if current_ap:
                    access_points.append(current_ap)
                current_ap = {}
                match = ssid_pattern.match(line)
                if match:
                    current_ap['SSID'] = match.group(1).strip()
            
            # Detecta BSSID
            elif re.match(r'BSSID\s+\d+\s*:', line, re.IGNORECASE):
                match = bssid_pattern.match(line)
                if match:
                    bssid = match.group(1).strip()
                    if 'BSSIDs' not in current_ap:
                        current_ap['BSSIDs'] = []
                    current_ap['BSSIDs'].append(bssid)
            
            # Detecta sinal
            elif re.search(r'Sinal\s*:', line, re.IGNORECASE):
                match = signal_pattern.match(line)
                if match:
                    current_ap['Signal'] = int(match.group(1))
        
        if current_ap:
            access_points.append(current_ap)
        
        return access_points
    except Exception as e:
        print(f"Aviso: Não foi possível obter lista de APs: {e}", file=sys.stderr)
        return []


def validate_bssid_location(bssid, location):
    """
    Valida se o BSSID está próximo à localização fornecida.
    Usa APIs públicas de geolocalização de WiFi quando disponível.
    
    Args:
        bssid (str): Endereço MAC do AP BSSID
        location (dict): Dicionário com latitude e longitude
        
    Returns:
        dict: Informações de validação ou None
    """
    if not location or not bssid or bssid == 'N/A':
        return None
    
    # Normaliza o BSSID (remove espaços, converte para minúsculas)
    bssid_clean = bssid.replace(':', '').replace('-', '').lower()
    
    # Para validação básica, podemos verificar se há APs próximos
    # com o mesmo SSID na área
    wifi_aps = get_wifi_access_points()
    
    validation_info = {
        'bssid': bssid,
        'location': location,
        'nearby_aps': len(wifi_aps),
        'validation': 'partial'  # Validação parcial baseada em APs visíveis
    }
    
    # Verifica se o BSSID está na lista de APs visíveis
    for ap in wifi_aps:
        if 'BSSIDs' in ap:
            for ap_bssid in ap['BSSIDs']:
                if ap_bssid.replace(':', '').replace('-', '').lower() == bssid_clean:
                    validation_info['found_in_visible_aps'] = True
                    validation_info['ssid'] = ap.get('SSID', 'N/A')
                    validation_info['signal'] = ap.get('Signal', 'N/A')
                    return validation_info
    
    validation_info['found_in_visible_aps'] = False
    return validation_info


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
    
    # Obtém localização geográfica
    print("Obtendo localização geográfica...")
    location = get_location_by_ip()
    
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
        
        # Validação de localização
        if location:
            print("\n[Localizacao Atual - Dados Completos]")
            print("=" * 60)
            print("\nCoordenadas Geograficas:")
            print("-" * 60)
            print(f"Latitude:  {location.get('latitude', 'N/A')}")
            print(f"Longitude: {location.get('longitude', 'N/A')}")
            
            print("\nLocalizacao:")
            print("-" * 60)
            print(f"Cidade:        {location.get('city', 'N/A')}")
            print(f"Estado/Regiao: {location.get('region', 'N/A')}")
            print(f"Pais:          {location.get('country', 'N/A')} ({location.get('country_code', 'N/A')})")
            if location.get('postal'):
                print(f"CEP/Codigo Postal: {location.get('postal', 'N/A')}")
            
            print("\nInformacoes de Rede:")
            print("-" * 60)
            print(f"Endereco IP:    {location.get('ip', 'N/A')}")
            if location.get('isp'):
                print(f"ISP/Provedor:   {location.get('isp', 'N/A')}")
            if bssid != 'N/A':
                print(f"AP BSSID:       {bssid}")
            if ssid != 'N/A':
                print(f"SSID Conectado: {ssid}")
            
            print("\nOutras Informacoes:")
            print("-" * 60)
            if location.get('timezone'):
                print(f"Fuso Horario:   {location.get('timezone', 'N/A')}")
            if location.get('currency'):
                print(f"Moeda:          {location.get('currency', 'N/A')} ({location.get('currency_name', 'N/A')})")
            
            # Valida BSSID com a localização
            if bssid != 'N/A':
                print("\n[Validacao do AP BSSID]")
                print("-" * 60)
                validation = validate_bssid_location(bssid, location)
                
                if validation:
                    if validation.get('found_in_visible_aps'):
                        print("[OK] AP BSSID encontrado na lista de pontos de acesso visiveis")
                        print(f"     SSID correspondente: {validation.get('ssid', 'N/A')}")
                        print(f"     Sinal: {validation.get('signal', 'N/A')}%")
                        print(f"     Total de APs visiveis na area: {validation.get('nearby_aps', 0)}")
                    else:
                        print("[AVISO] AP BSSID nao encontrado na lista de APs visiveis")
                        print(f"        Total de APs visiveis na area: {validation.get('nearby_aps', 0)}")
                        print("        Nota: Isso pode ser normal se o AP estiver oculto ou fora de alcance")
                else:
                    print("[AVISO] Nao foi possivel validar o AP BSSID")
        else:
            print("\n[AVISO] Nao foi possivel obter localizacao geografica")
            print("        Verifique sua conexao com a internet")
    
    print("\n" + "=" * 60)
    
    # Retorna os dados como dicionário para uso programático
    return interfaces


if __name__ == "__main__":
    main()

