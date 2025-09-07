# pylint: disable=missing-module-docstring
# pylint: disable=W0718
# pylint: disable=W1203

import sys
import os
import getpass
import time
import csv
import logging
# from datetime import datetime
import requests

# Configuración de logging
logging.basicConfig(
    filename="registro.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Validación de argumentos
if len(sys.argv) != 2:
    print("Uso: python verificar_correo.py correo@example.com")
    logging.error("Número incorrecto de argumentos. Se esperaba 1 (correo).")
    sys.exit(1)

correo = sys.argv[1]

API_KEY_PATH = "apikey.txt"
if not os.path.exists(API_KEY_PATH):
    print("No se encontró el archivo apikey.txt.")
    clave = getpass.getpass("Ingresa tu API key: ")
    try:
        with open(API_KEY_PATH, "w", encoding="utf-8") as archivo:
            archivo.write(clave.strip())
    except Exception as e:
        logging.error(f"No se pudo guardar la API key: {e}")
        sys.exit(1)

# Carga de API key
try:
    with open(API_KEY_PATH, "r", encoding="utf-8") as archivo:
        api_key = archivo.read().strip()
except Exception as e:
    print("Error al leer la API key.")
    logging.error(f"Error al leer apikey.txt: {e}")
    sys.exit(1)

# Consulta inicial a la API
URL = f"https://haveibeenpwned.com/api/v3/breachedaccount/{correo}"
headers = {
    "hibp-api-key": api_key,
    "user-agent": "PythonScript"
}

try:
    response = requests.get(URL, headers=headers, timeout=10)
except Exception as e:
    print("Error al conectar con la API.")
    logging.error(f"Error de conexión: {e}")
    sys.exit(1)

# Procesamiento de respuesta recibida
if response.status_code == 200:
    brechas = response.json()
    logging.info(f"Consulta exitosa para {correo}. Brechas encontradas: "
                 f"{len(brechas)}")

    # Preparación del archivo CSV
    try:
        with open("reporte.csv", "w", newline='', encoding="utf-8") as archivo_csv:
            writer = csv.writer(archivo_csv)
            writer.writerow(["Título", "Dominio", "Fecha de Brecha",
                             "Datos Comprometidos",
                             "Verificada",
                             "Sensible"])

            for i, brecha in enumerate(brechas[:3]):
                nombre = brecha['Name']
                DETALLE_URL = f"https://haveibeenpwned.com/api/v3/breach/{nombre}"
                try:
                    detalle_resp = requests.get(DETALLE_URL, headers=headers,
                                                timeout=10)
                    if detalle_resp.status_code == 200:
                        detalle = detalle_resp.json()
                        writer.writerow([
                            detalle.get("Title"),
                            detalle.get("Domain"),
                            detalle.get("BreachDate"),
                            ", ".join(detalle.get("DataClasses", [])),
                            "Sí" if detalle.get("IsVerified") else "No",
                            "Sí" if detalle.get("IsSensitive") else "No"
                        ])
                    else:
                        logging.error("No se pudo obtener detalles de la "
                                      f"brecha: {nombre}. "
                                      f"Código: {detalle_resp.status_code}")
                except Exception as e:
                    logging.error(f"Error al consultar detalles de la brecha "
                                  f"{nombre}: {e}")

                if i < 2:
                    time.sleep(10)  # tiempo de espera entre consultas
    except Exception as e:
        print("Error al generar el archivo CSV.")
        logging.error(f"Error al escribir reporte.csv: {e}")
        sys.exit(1)

    print("Consulta completada. Revisa el archivo reporte.csv "
          "para ver los resultados.")
elif response.status_code == 404:
    print(f"La cuenta {correo} no aparece en ninguna brecha conocida.")
    logging.info(f"Consulta exitosa para {correo}. "
                 f"No se encontraron brechas.")
elif response.status_code == 401:
    print("Error de autenticación: revisa tu API key.")
    logging.error("Error 401: API key inválida.")
else:
    print(f"Error inesperado. Código de estado: {response.status_code}")
    logging.error(f"Error inesperado. Código de estado: "
                  f"{response.status_code}")
