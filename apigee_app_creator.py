#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apigee_app_creator.py

Script interactivo para facilitar la creación de Developer Apps en Apigee
usando un servidor propio de autenticación (SOS) para generar y registrar
el clientID/clientSecret.

Flujo:
    1. Selección de área Apigee (Western / Germany), organización y entorno.
    2. Selección/validación de producto Apigee (si no existe o se deja en
       blanco, se listan los productos disponibles para esa org/env).
    3. Introducción (o generación aleatoria) de clientID/clientSecret.
    4. Comprobación de disponibilidad del clientID en SOS y en Apigee.
    5. Introducción obligatoria de scopes y grants (jwt / client_credentials).
    6. Creación del cliente en SOS + asignación de scopes.
    7. Creación de la Developer App en Apigee + asociación del producto.
    8. Mensaje final con las credenciales y texto listo para pegar en SNOW.

Uso:
    python3 apigee_app_creator.py
    python3 apigee_app_creator.py --help

IMPORTANTE:
    - Rellena las URLs y la lógica de autenticación reales de SOS/Apigee
      en las clases SOSClient y ApigeeClient (marcadas con TODO).
    - Las credenciales de servicio (para llamar a SOS/Apigee, NO las que
      genera el script) se leen de un fichero externo config/credentials.json
      que NO debe subirse a ningún repositorio (añádelo a .gitignore).
"""

import argparse
import json
import logging
import os
import re
import secrets
import string
import sys
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit(
        "Falta la librería 'requests'. Instálala con: pip install requests"
    )

# ---------------------------------------------------------------------------
# Configuración general
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
CREDENTIALS_FILE = BASE_DIR / "config" / "credentials.json"
LOG_DIR = BASE_DIR / "logs"
SECRETS_DIR = BASE_DIR / "secrets"

# Grupo del SO al que se le da permiso de lectura sobre los ficheros de
# secretos generados (además del propietario). Déjalo en None para no
# tocar el group ownership. Solo tiene efecto en Unix.
SECRETS_GROUP = os.environ.get("APIGEE_SCRIPT_SECRETS_GROUP")  # p.ej. "apigee-admins"

VALID_GRANTS = {"jwt", "client_credentials"}
AREAS = {"1": "western", "2": "germany"}
ENVIRONMENTS = {"1": "dev", "2": "pre"}

INTRO_TEXT = """
==============================================================================
 Creador de Developer Apps en Apigee (vía SOS)
==============================================================================
AVISO IMPORTANTE:
  Este script SOLO crea aplicaciones en SOS / Apigee para la LANDING ZONE
  REGIONAL. Para la Landing Zone 2, el proceso se realiza de forma MANUAL
  y requiere autorización expresa. Si necesitas Landing Zone 2, detén la
  ejecución ahora y sigue el procedimiento manual correspondiente.

Antes de continuar, ten a mano la siguiente información:

  - Área Apigee: Western o Germany
  - Entorno de Apigee: dev o pre
    (la organización se determina automáticamente según área + entorno)
  - Producto (o productos) de Apigee que quieres asociar a la app
  - Scopes que necesita el cliente (obligatorio)
  - Grant type(s): 'client_credentials', 'jwt', o ambos

Recuerda:
  - El sos_clientID y el ui_clientID de Apigee son EL MISMO valor.
  - El clientSecret NO se envía nunca a Apigee, solo se usa en el SOS.
  - Todos los inputs se limpian de espacios al principio/final.
  - El clientSecret se guardará en un fichero con permisos restringidos,
    NO en el log general.
==============================================================================
"""

SNOW_TEMPLATE = """\
Se han generado las credenciales solicitadas.

El clientID es: {client_id}

Póngase en contacto con el equipo para obtener el clientSecret vía Teams.
"""

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def setup_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = LOG_DIR / f"apigee_app_creator_{ts}.log"

    logger = logging.getLogger("apigee_app_creator")
    logger.setLevel(logging.INFO)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(fh)
    logger.addHandler(ch)

    # El fichero de log general NUNCA debe contener secretos (ver
    # secure logger más abajo para eso).
    try:
        os.chmod(log_path, 0o640)
    except (PermissionError, NotImplementedError, OSError):
        pass

    logger.info("=== Nueva ejecución del script ===")
    return logger


def setup_secure_logger() -> logging.Logger:
    """Logger separado, con permisos restringidos, para los ÚNICOS datos
    sensibles (clientSecret) que sí hay que dejar registrados a petición.
    """
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    secure_log_path = SECRETS_DIR / f"credentials_{ts}.log"

    secure_logger = logging.getLogger("apigee_app_creator.secure")
    secure_logger.setLevel(logging.INFO)
    secure_logger.propagate = False  # que no se filtre al logger general

    fh = logging.FileHandler(secure_log_path, encoding="utf-8")
    fh.setFormatter(
        logging.Formatter("%(asctime)s | %(message)s")
    )
    secure_logger.addHandler(fh)

    _restrict_permissions(secure_log_path)
    return secure_logger


def _restrict_permissions(path: Path) -> None:
    """Deja el fichero legible únicamente por el propietario (y
    opcionalmente por el grupo indicado en SECRETS_GROUP). Best-effort,
    solo tiene efecto real en sistemas Unix."""
    try:
        if SECRETS_GROUP:
            import grp
            gid = grp.getgrnam(SECRETS_GROUP).gr_gid
            os.chown(path, -1, gid)
            os.chmod(path, 0o640)  # rw- r-- ---
        else:
            os.chmod(path, 0o600)  # rw- --- ---
    except (PermissionError, NotImplementedError, OSError, KeyError):
        # En Windows, o si no hay permisos suficientes para chown/chmod,
        # se deja pasar pero se recomienda restringir el acceso a la
        # carpeta 'secrets/' por otros medios (ACLs, ubicación protegida).
        pass


# ---------------------------------------------------------------------------
# Utilidades de input
# ---------------------------------------------------------------------------


def clean_input(prompt: str, required: bool = False) -> str:
    """Pide un input, elimina espacios al principio/final y repite si
    'required' es True y el usuario no introduce nada."""
    while True:
        value = input(prompt).strip()
        if required and not value:
            print("  -> Este campo es obligatorio.")
            continue
        return value


def confirm(prompt: str) -> bool:
    resp = clean_input(f"{prompt} (s/n): ").lower()
    return resp in ("s", "si", "sí", "y", "yes")


def generate_random_credential(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def validate_grants(raw: str, logger: logging.Logger) -> list[str]:
    """Valida que los grants introducidos sean jwt y/o client_credentials."""
    while True:
        parts = [p.strip().lower() for p in raw.split(",") if p.strip()]
        invalid = [p for p in parts if p not in VALID_GRANTS]
        if invalid or not parts:
            print(
                "  -> Grant(s) no válido(s): "
                f"{invalid if invalid else '(vacío)'}. "
                "Solo se permiten 'client_credentials' y/o 'jwt'."
            )
            raw = clean_input(
                "  Introduce grant(s) separados por coma "
                "(client_credentials, jwt): ",
                required=True,
            )
            continue
        logger.info("Grants seleccionados: %s", parts)
        return parts


# ---------------------------------------------------------------------------
# Credenciales de servicio (para llamar a SOS/Apigee)
# ---------------------------------------------------------------------------


def load_service_credentials() -> dict:
    """Carga credenciales de servicio desde config/credentials.json.

    Estructura esperada (ver config/credentials.example.json):

        {
          "western": {
            "dev": {
              "org": "org-western-dev",
              "sos_base_url": "https://sos.western.example.com",
              "apigee_base_url": "https://api.western.apigee.example.com",
              "sos_user": "...", "sos_password": "...",
              "apigee_user": "...", "apigee_password": "..."
            },
            "pre": { ... }
          },
          "germany": {
            "dev": { ... },
            "pre": { ... }
          }
        }

    Cada combinación área+entorno tiene su propia organización y sus
    propias credenciales de SOS/Apigee, porque son distintas por área
    y por entorno.

    NOTA sobre protección del fichero:
      - En sistemas Unix, tras crearlo, se recomienda:
            chmod 600 config/credentials.json
        (o 640 + grupo restringido si varias personas deben poder leerlo).
      - En Windows no existe un equivalente directo; considera usar
        variables de entorno, un gestor de secretos (Vault, AWS Secrets
        Manager, etc.) o el Credential Manager del SO en vez de un JSON
        plano si el script se va a usar fuera de Linux/Mac.
      - Asegúrate de añadir config/credentials.json al .gitignore.
    """
    if not CREDENTIALS_FILE.exists():
        sys.exit(
            f"No se encuentra el fichero de credenciales de servicio: "
            f"{CREDENTIALS_FILE}\n"
            "Crea config/credentials.json con la estructura esperada "
            "(ver config/credentials.example.json)."
        )
    with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    _restrict_permissions(CREDENTIALS_FILE)
    return data


def get_context_credentials(all_creds: dict, area: str, env: str) -> dict:
    """Devuelve el bloque de configuración (org + credenciales SOS/Apigee)
    correspondiente a la combinación área+entorno seleccionada."""
    try:
        ctx = all_creds[area][env]
    except KeyError:
        sys.exit(
            f"No hay configuración de credenciales para área='{area}' "
            f"entorno='{env}' en {CREDENTIALS_FILE}."
        )
    required_keys = {
        "org", "sos_base_url", "apigee_base_url",
        "sos_user", "sos_password", "apigee_user", "apigee_password",
    }
    missing = required_keys - ctx.keys()
    if missing:
        sys.exit(
            f"Faltan claves {missing} en credentials.json para "
            f"{area}/{env}."
        )
    return ctx


# ---------------------------------------------------------------------------
# Cliente SOS
# ---------------------------------------------------------------------------


class SOSClient:
    """Wrapper de llamadas al servidor propio de autenticación (SOS).

    TODO: Ajustar endpoints y estructura de payload/response reales de tu
    SOS. La autenticación se hace por defecto con Basic Auth (usuario y
    contraseña específicos del área+entorno); si tu SOS usa un esquema
    distinto (p.ej. intercambio de token OAuth2 previo), sustituye
    self._auth / self._headers en consecuencia.
    """

    def __init__(self, area: str, env: str, ctx: dict, logger: logging.Logger):
        self.area = area
        self.env = env
        self.logger = logger
        self.base_url = ctx["sos_base_url"].rstrip("/")
        self._auth = requests.auth.HTTPBasicAuth(
            ctx["sos_user"], ctx["sos_password"]
        )

    def _headers(self) -> dict:
        return {"Content-Type": "application/json"}

    def client_id_exists(self, client_id: str) -> bool:
        # TODO: endpoint real, p.ej. GET {base_url}/clients/{client_id}
        url = f"{self.base_url}/clients/{client_id}"
        try:
            resp = requests.get(
                url, headers=self._headers(), auth=self._auth, timeout=15
            )
        except requests.RequestException as exc:
            self.logger.error("Error comprobando clientID en SOS: %s", exc)
            sys.exit("No se pudo contactar con el SOS. Aborta.")
        if resp.status_code == 200:
            return True
        if resp.status_code == 404:
            return False
        self.logger.error(
            "Respuesta inesperada del SOS al comprobar clientID (%s): %s",
            resp.status_code,
            resp.text,
        )
        sys.exit("Respuesta inesperada del SOS. Aborta.")

    def create_client(self, client_id: str, client_secret: str) -> None:
        # TODO: endpoint real, p.ej. POST {base_url}/clients
        url = f"{self.base_url}/clients"
        payload = {"clientId": client_id, "clientSecret": client_secret}
        resp = requests.post(
            url, headers=self._headers(), auth=self._auth, json=payload,
            timeout=15,
        )
        if not resp.ok:
            self.logger.error(
                "Fallo creando cliente en SOS (%s): %s",
                resp.status_code,
                resp.text,
            )
            sys.exit("No se pudo crear el cliente en el SOS. Aborta.")
        self.logger.info("Cliente creado en SOS: %s", client_id)

    def add_scopes(self, client_id: str, scopes: str, grants: list[str]) -> None:
        # TODO: endpoint real, p.ej. POST {base_url}/clients/{client_id}/scopes
        url = f"{self.base_url}/clients/{client_id}/scopes"
        payload = {"scopes": scopes, "grants": grants}
        resp = requests.post(
            url, headers=self._headers(), auth=self._auth, json=payload,
            timeout=15,
        )
        if not resp.ok:
            self.logger.error(
                "Fallo añadiendo scopes en SOS (%s): %s",
                resp.status_code,
                resp.text,
            )
            sys.exit("No se pudieron añadir los scopes en el SOS. Aborta.")
        self.logger.info(
            "Scopes '%s' y grants %s añadidos a %s", scopes, grants, client_id
        )

    def delete_client(self, client_id: str) -> bool:
        """Rollback: elimina el cliente del SOS. Se usa cuando la creación
        de la Developer App en Apigee falla después de haber creado el
        cliente en el SOS, para no dejar el clientID "huérfano".

        Devuelve True si el borrado fue correcto, False en caso contrario
        (en cuyo caso hay que avisar para limpieza manual).
        """
        # TODO: endpoint real, p.ej. DELETE {base_url}/clients/{client_id}
        url = f"{self.base_url}/clients/{client_id}"
        try:
            resp = requests.delete(
                url, headers=self._headers(), auth=self._auth, timeout=15
            )
        except requests.RequestException as exc:
            self.logger.error(
                "Error de red haciendo rollback (delete) en SOS: %s", exc
            )
            return False
        if resp.ok:
            self.logger.info("Rollback OK: cliente %s eliminado del SOS", client_id)
            return True
        self.logger.error(
            "Rollback FALLIDO eliminando %s del SOS (%s): %s",
            client_id, resp.status_code, resp.text,
        )
        return False


# ---------------------------------------------------------------------------
# Cliente Apigee
# ---------------------------------------------------------------------------


class ApigeeClient:
    """Wrapper de llamadas a la Management API de Apigee.

    TODO: Ajustar base_url, endpoints y autenticación real (OAuth2 con
    Google service account, token de acceso, etc.) según tu organización.
    """

    def __init__(self, area: str, env: str, ctx: dict, logger: logging.Logger):
        self.area = area
        self.env = env
        self.org = ctx["org"]
        self.logger = logger
        self.base_url = ctx["apigee_base_url"].rstrip("/")
        self._auth = requests.auth.HTTPBasicAuth(
            ctx["apigee_user"], ctx["apigee_password"]
        )
        # TODO: si Apigee requiere OAuth2 (token de Google, SAPI token,
        # etc.) en vez de Basic Auth, sustituye self._auth por la lógica
        # de obtención/renovación de token correspondiente.

    def _headers(self) -> dict:
        return {"Content-Type": "application/json"}

    def list_products(self) -> list[str]:
        # TODO: endpoint real, p.ej.
        # GET {base_url}/v1/organizations/{org}/apiproducts
        url = f"{self.base_url}/v1/organizations/{self.org}/apiproducts"
        resp = requests.get(
            url, headers=self._headers(), auth=self._auth, timeout=15
        )
        if not resp.ok:
            self.logger.error(
                "Fallo listando productos de Apigee (%s): %s",
                resp.status_code,
                resp.text,
            )
            sys.exit("No se pudieron listar los productos de Apigee. Aborta.")
        return resp.json().get("apiProduct", resp.json())

    def product_exists(self, product: str) -> bool:
        products = self.list_products()
        # Ajustar según la forma real de la respuesta (lista de dicts o de str)
        names = [
            p if isinstance(p, str) else p.get("name") for p in products
        ]
        return product in names

    def client_id_exists(self, client_id: str) -> bool:
        # TODO: endpoint real para comprobar si un clientID/app ya existe,
        # p.ej. buscar apps de desarrollador por credencial.
        url = (
            f"{self.base_url}/v1/organizations/{self.org}/apps"
            f"?apiKey={client_id}"
        )
        resp = requests.get(
            url, headers=self._headers(), auth=self._auth, timeout=15
        )
        if resp.status_code == 200:
            return True
        if resp.status_code == 404:
            return False
        self.logger.error(
            "Respuesta inesperada de Apigee al comprobar clientID (%s): %s",
            resp.status_code,
            resp.text,
        )
        sys.exit("Respuesta inesperada de Apigee. Aborta.")

    def create_developer_app(self, developer_email: str, app_name: str,
                              client_id: str, product: str) -> None:
        """Crea la Developer App con el clientID como credencial (sin
        secret) y le asocia el producto solicitado."""
        # TODO: endpoint real, p.ej.
        # POST {base_url}/v1/organizations/{org}/developers/{developer}/apps
        url = (
            f"{self.base_url}/v1/organizations/{self.org}"
            f"/developers/{developer_email}/apps"
        )
        payload = {
            "name": app_name,
            "apiProducts": [product],
            "credentials": [{"consumerKey": client_id, "consumerSecret": ""}],
        }
        resp = requests.post(
            url, headers=self._headers(), auth=self._auth, json=payload,
            timeout=20,
        )
        if not resp.ok:
            self.logger.error(
                "Fallo creando Developer App en Apigee (%s): %s",
                resp.status_code,
                resp.text,
            )
            # No usamos sys.exit aquí: se lanza una excepción para que
            # main() pueda hacer rollback del cliente creado en el SOS
            # antes de terminar la ejecución.
            raise RuntimeError(
                f"No se pudo crear la Developer App en Apigee "
                f"({resp.status_code}): {resp.text}"
            )
        self.logger.info(
            "Developer App '%s' creada en Apigee con producto '%s'",
            app_name,
            product,
        )


# ---------------------------------------------------------------------------
# Flujo principal
# ---------------------------------------------------------------------------


def select_area(logger: logging.Logger) -> str:
    print("\nSelecciona el área de Apigee:")
    print("  1) Western")
    print("  2) Germany")
    while True:
        choice = clean_input("Opción (1/2): ", required=True)
        if choice in AREAS:
            area = AREAS[choice]
            logger.info("Área seleccionada: %s", area)
            return area
        print("  -> Opción no válida.")


def select_environment(logger: logging.Logger) -> str:
    print("\nSelecciona el entorno:")
    print("  1) dev")
    print("  2) pre")
    while True:
        choice = clean_input("Opción (1/2): ", required=True)
        if choice in ENVIRONMENTS:
            env = ENVIRONMENTS[choice]
            logger.info("Entorno seleccionado: %s", env)
            return env
        print("  -> Opción no válida.")


def select_product(apigee: ApigeeClient, logger: logging.Logger) -> str:
    product = clean_input(
        "\nProducto de Apigee a asociar (vacío para ver la lista): "
    )
    while not product or not apigee.product_exists(product):
        if product:
            print(f"  -> El producto '{product}' no existe para "
                  f"{apigee.org}/{apigee.env}.")
        products = apigee.list_products()
        names = [p if isinstance(p, str) else p.get("name") for p in products]
        print("\nProductos disponibles para "
              f"org='{apigee.org}', env='{apigee.env}', area='{apigee.area}':")
        for n in names:
            print(f"  - {n}")
        product = clean_input("Introduce el producto exacto: ", required=True)
    logger.info("Producto seleccionado: %s", product)
    return product


def get_or_generate_credentials(logger: logging.Logger) -> tuple[str, str]:
    print("\nIntroduce el clientID y clientSecret deseados.")
    print("(Déjalos vacíos para generarlos automáticamente)")
    client_id = clean_input("clientID: ")
    client_secret = clean_input("clientSecret: ")

    generated = False
    if not client_id:
        client_id = generate_random_credential(24)
        generated = True
    if not client_secret:
        client_secret = generate_random_credential(40)
        generated = True

    if generated:
        print(f"\nSe ha(n) generado automáticamente:")
        print(f"  clientID:     {client_id}")
        print(f"  clientSecret: {'*' * len(client_secret)} (oculto en pantalla)")
        if not confirm("¿Confirmas el uso de estas credenciales generadas?"):
            sys.exit("Operación cancelada por el usuario.")

    logger.info("clientID a utilizar: %s", client_id)
    logger.info("clientSecret generado automáticamente: %s", generated)
    return client_id, client_secret


def check_availability(sos: SOSClient, apigee: ApigeeClient, client_id: str,
                        logger: logging.Logger) -> None:
    print("\nComprobando disponibilidad del clientID...")
    if sos.client_id_exists(client_id):
        logger.warning("clientID ya existe en SOS: %s", client_id)
        sys.exit(f"El clientID '{client_id}' ya existe en el SOS. Aborta.")
    if apigee.client_id_exists(client_id):
        logger.warning("clientID ya existe en Apigee: %s", client_id)
        sys.exit(f"El clientID '{client_id}' ya existe en Apigee. Aborta.")
    print("clientID disponible en SOS y en Apigee.")
    logger.info("clientID '%s' disponible en ambas plataformas.", client_id)


def get_scopes_and_grants(logger: logging.Logger) -> tuple[str, list[str]]:
    scopes = clean_input(
        "\nScope(s) para el SOS (obligatorio, separados por espacio): ",
        required=True,
    )
    logger.info("Scopes introducidos: %s", scopes)

    grants_raw = clean_input(
        "Grant(s) [client_credentials, jwt, o ambos separados por coma]: ",
        required=True,
    )
    grants = validate_grants(grants_raw, logger)
    return scopes, grants


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apigee_app_creator.py",
        description=(
            "Automatiza la creación de un clientID/clientSecret en el SOS "
            "y la creación de la Developer App correspondiente en Apigee "
            "(Western o Germany), incluyendo validación de producto, "
            "scopes y grant types."
        ),
        epilog=(
            "Ejemplo: python3 apigee_app_creator.py\n"
            "El script es interactivo: te irá guiando paso a paso."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    return parser


def store_secret_securely(secure_logger: logging.Logger, client_id: str,
                           client_secret: str, area: str, env: str,
                           org: str, scopes: str, grants: list[str]) -> Path:
    """Guarda el clientSecret en un fichero individual con permisos
    restringidos (además de dejar constancia en el log seguro)."""
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    secret_path = SECRETS_DIR / f"{client_id}_{ts}.json"

    payload = {
        "timestamp": datetime.now().isoformat(),
        "area": area,
        "env": env,
        "org": org,
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": scopes,
        "grants": grants,
    }
    with open(secret_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    _restrict_permissions(secret_path)

    secure_logger.info(
        "clientID=%s | clientSecret=%s | area=%s | env=%s | org=%s | "
        "scopes='%s' | grants=%s | fichero=%s",
        client_id, client_secret, area, env, org, scopes, grants, secret_path,
    )
    return secret_path


def confirm_landing_zone(logger: logging.Logger) -> None:
    print(
        "Este script SOLO opera sobre la Landing Zone Regional.\n"
        "Para Landing Zone 2 debes seguir el proceso MANUAL con "
        "autorización expresa."
    )
    if not confirm("¿Confirmas que esta petición es para la Landing Zone Regional?"):
        logger.info("Ejecución cancelada: la petición no es para Landing Zone Regional.")
        sys.exit(
            "Ejecución cancelada. Sigue el proceso manual para Landing Zone 2."
        )


def main() -> None:
    parser = build_parser()
    parser.parse_args()  # solo para soportar -h/--help por ahora

    logger = setup_logging()
    secure_logger = setup_secure_logger()
    print(INTRO_TEXT)

    confirm_landing_zone(logger)

    all_creds = load_service_credentials()

    area = select_area(logger)
    env = select_environment(logger)
    ctx = get_context_credentials(all_creds, area, env)
    org = ctx["org"]
    print(f"\nOrganización resuelta automáticamente: {org} "
          f"(área={area}, entorno={env})")
    logger.info("Organización: %s | Entorno: %s | Área: %s", org, env, area)

    sos = SOSClient(area, env, ctx, logger)
    apigee = ApigeeClient(area, env, ctx, logger)

    product = select_product(apigee, logger)

    client_id, client_secret = get_or_generate_credentials(logger)
    check_availability(sos, apigee, client_id, logger)

    scopes, grants = get_scopes_and_grants(logger)

    # sos_clientID == ui_clientID (Apigee) == client_id
    print("\nCreando cliente en el SOS...")
    sos.create_client(client_id, client_secret)
    sos.add_scopes(client_id, scopes, grants)

    developer_email = clean_input(
        "\nEmail del developer de Apigee al que asociar la app: ",
        required=True,
    )
    app_name = clean_input(
        "Nombre de la Developer App a crear: ", required=True
    )

    print("Creando Developer App en Apigee y asociando el producto...")
    try:
        apigee.create_developer_app(developer_email, app_name, client_id, product)
    except RuntimeError as exc:
        logger.error("Fallo creando la Developer App: %s", exc)
        print(f"\nERROR creando la Developer App en Apigee: {exc}")
        print("Haciendo rollback: eliminando el clientID del SOS...")
        rollback_ok = sos.delete_client(client_id)
        if rollback_ok:
            print("Rollback completado: el clientID se ha eliminado del SOS.")
        else:
            print(
                "ATENCIÓN: el rollback automático ha fallado. "
                f"Elimina manualmente el clientID '{client_id}' del SOS."
            )
            logger.error(
                "Rollback manual requerido para clientID=%s", client_id
            )
        sys.exit(1)

    # Solo se persiste el secreto una vez todo el flujo se ha completado
    # con éxito, y en un fichero con permisos restringidos.
    secret_path = store_secret_securely(
        secure_logger, client_id, client_secret, area, env, org, scopes, grants
    )

    print("\n" + "=" * 78)
    print("¡Proceso completado con éxito!")
    print(f"  clientID:     {client_id}")
    print(f"  clientSecret: {client_secret}")
    print(f"  (credenciales guardadas de forma restringida en: {secret_path})")
    print("=" * 78)

    print("\nTexto para copiar en SNOW:\n")
    print(SNOW_TEMPLATE.format(client_id=client_id))

    logger.info("Proceso finalizado correctamente para clientID=%s", client_id)
    logger.info(
        "clientSecret guardado en fichero restringido: %s "
        "(no se ha escrito en el log general)", secret_path
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperación cancelada por el usuario.")
        sys.exit(1)
