# pylint: disable=missing-module-docstring
# pylint: disable=C0116
import os
import argparse
import getpass
import logging
import csv
import requests


def leer_apikey(path="apikey.txt"):
    if not os.path.exists(path):
        clave = getpass.getpass("Ingresa tu API key: ")
        with open(path, "w", encoding="utf-8", errors="ignore") as archivo:
            archivo.write(clave.strip())
    with open(path, "r", encoding="utf-8", errors="ignore") as archivo:
        return archivo.read().strip()


def obtener_argumentos():
    parser = argparse.ArgumentParser(
        description="Verifica si un correo ha sido comprometido usando "
                    "la API de Have I Been Pwned."
    )
    parser.add_argument("correo", help="Correo electronico a verificar")
    parser.add_argument("-o", "--output", default="reporte.csv",
                        help="Nombre del archivo CSV de salida")
    return parser.parse_args()


def consultar_brechas(correo, api_key):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{correo}"
    headers = {"hibp-api-key": api_key, "user-agent": "PythonScript"}
    return requests.get(url, headers=headers, timeout=10)


def consultar_detalle(nombre, api_key):
    url = f"https://haveibeenpwned.com/api/v3/breach/{nombre}"
    headers = {"hibp-api-key": api_key, "user-agent": "PythonScript"}
    return requests.get(url, headers=headers, timeout=10)


def generar_csv(nombre_archivo, lista_detalles):
    with open(nombre_archivo, "w", newline='', encoding="utf-8", errors="ignore") as archivo_csv:
        writer = csv.writer(archivo_csv)
        writer.writerow(["Titulo", "Dominio", "Fecha de Brecha",
                         "Datos Comprometidos",
                         "Verificada",
                         "Sensible"])
        for detalle in lista_detalles:
            writer.writerow([
                detalle.get("Title"),
                detalle.get("Domain"),
                detalle.get("BreachDate"),
                ", ".join(detalle.get("DataClasses", [])),
                "Si" if detalle.get("IsVerified") else "No",
                "Si" if detalle.get("IsSensitive") else "No"
            ])


logging.basicConfig(
    filename="registro.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
