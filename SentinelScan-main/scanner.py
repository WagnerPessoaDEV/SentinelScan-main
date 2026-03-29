# -*- coding: utf-8 -*-
import socket
import sys
from datetime import datetime
from pathlib import Path

# Configurar saida para UTF-8 para evitar erros de codificacao em terminais Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Portas conhecidas
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
}

# Classificacao de risco
HIGH_RISK_PORTS = {21, 23, 445, 3389}
MEDIUM_RISK_PORTS = {22, 25, 110, 139, 143, 3306}


def print_banner():
    print("=" * 60)
    print("SentinelScan - Scanner Inteligente de Portas")
    print("=" * 60)
    print("Wagner Pessoa.\n")


def resolve_target(target):
    while True:
        try:
            return socket.gethostbyname(target)
        except:
            print("[!] Erro ao resolver o host. Verifique se o IP ou dominio esta correto.")
            target = input("Digite o IP ou dominio novamente: ")


def classify_port(port):
    if port in HIGH_RISK_PORTS:
        return "Alto risco"
    elif port in MEDIUM_RISK_PORTS:
        return "Medio risco"
    return "Baixo risco"


def get_service(port):
    return COMMON_PORTS.get(port, "Desconhecido")


def scan_ports(ip, start_port, end_port):
    open_ports = []

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((ip, port))

        if result == 0:
            service = get_service(port)
            risk = classify_port(port)

            print(f"🚪 Porta {port} | Servico: {service} | Risco: {risk}")

            open_ports.append({
                "port": port,
                "service": service,
                "risk": risk
            })

        sock.close()

    return open_ports


def generate_report(target, ip, open_ports, start, end, inicio, fim):
    path = Path("report.txt")

    with open(path, "w", encoding="utf-8") as file:
        file.write("SentinelScan - Relatorio\n")
        file.write("=" * 40 + "\n")
        file.write(f"Alvo: {target}\n")
        file.write(f"IP: {ip}\n")
        file.write(f"Portas: {start} - {end}\n")
        file.write(f"Inicio: {inicio}\n")
        file.write(f"Fim: {fim}\n\n")

        if open_ports:
            file.write("Portas abertas:\n")
            for p in open_ports:
                file.write(f"- Porta {p['port']} | {p['service']} | {p['risk']}\n")
        else:
            file.write("Nenhuma porta aberta encontrada.\n")

    return path


def get_port_input(prompt):
    while True:
        try:
            return int(input(prompt))
        except ValueError:
            print("[!] Por favor, digite apenas numeros.")


def main():
    print_banner()

    target = input("Digite o IP ou dominio (ex: google.com ou 127.0.0.1): ")
    ip = resolve_target(target)

    print(f"\n🎯 Alvo: {target}")
    print(f"🌐 IP: {ip}")

    # Intervalo padrao + opcao personalizada
    print("\n⚠️  Intervalo padrao recomendado: 1 a 1024")
    usar_padrao = input("Deseja usar o padrao? (s/n): ").lower()

    if usar_padrao == "s":
        start_port = 1
        end_port = 1024
    else:
        start_port = get_port_input("Porta inicial: ")
        end_port = get_port_input("Porta final: ")


    inicio = datetime.now()

    open_ports = scan_ports(ip, start_port, end_port)

    fim = datetime.now()

    print("\n" + "=" * 60)
    print("✅ Escaneamento finalizado")
    print(f"🕛​ Inicio: {inicio}")
    print(f"🕐 Fim: {fim}")
    print(f"📊​ Total de portas abertas: {len(open_ports)}")

    # Analise de risco
    high = sum(1 for p in open_ports if p["risk"] == "Alto risco")
    medium = sum(1 for p in open_ports if p["risk"] == "Medio risco")
    low = sum(1 for p in open_ports if p["risk"] == "Baixo risco")

    print("\n⚠️  Classificacao de risco:")
    print(f"🔴 Alto risco: {high}")
    print(f"🟡 Medio risco: {medium}")
    print(f"🟢 Baixo risco: {low}")

    if open_ports:
        print("\nResumo:")
        for p in open_ports:
            print(f"- Porta {p['port']} | {p['service']} | {p['risk']}")
    else:
        print("Nenhuma porta aberta encontrada.")

    report = generate_report(target, ip, open_ports, start_port, end_port, inicio, fim)

    print("\n📃 Relatorio gerado com sucesso!")
    print(f"📂 Local: {report.resolve()}")

    print("\n🔎 Analise concluida.")
    print("⚠️  Recomenda-se aplicar boas praticas de seguranca.")

    print("\n🖥️  Desenvolvido por Wagner Pessoa")
    print("=" * 60)

    input("\nPressione Enter para sair...")


if __name__ == "__main__":
    main()
