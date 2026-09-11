"""Alertas escalonadas de vencimiento para secrets de Secrets Manager y parámetros SSM.

Escanea cada secret/parámetro tageado con `expires=YYYY-MM-DD` en la cuenta
--dentro de la región donde se ejecuta esta función, porque la Resource Groups
Tagging API es regional-- y publica una alerta por SNS una vez por recurso,
cada vez que cruza un tier
más ajustado dentro de (30, 14, 7, 1) días para el vencimiento; una alerta
que se repite a diario una vez que el recurso ya venció; y una alerta única
para un valor `expires` no parseable.

El estado se trackea directamente sobre el recurso vía tres tags que esta
función escribe de vuelta: `expires-alerted-for` (el valor crudo de `expires`
contra el que se calculó la última alerta), `expires-alerted-tier` (el tier
más ajustado alertado para ese valor: uno de "30", "14", "7", "1", "overdue",
"malformed"), y `expires-alerted-date` (la fecha, en UTC, de esa última
alerta). Comparar el valor actual de `expires` del recurso contra
`expires-alerted-for` es lo que hace que una rotación (o una edición manual)
resetee el ciclo, en vez de depender de que esta función se ejecute justo en un
día calendario particular. `expires-alerted-date` cumple un rol distinto:
mientras que cada tier (30/14/7/1) sólo se alerta una vez, "overdue" está 
pensado para repetirse mientras la credencial siga vencida, pero como máximo 
una vez por día calendario en UTC:
sin este tag, invocar la función más de una vez el mismo día (a mano, o si
el schedule alguna vez se dispara más seguido) manda esa alerta de nuevo cada vez,
en lugar de una sola vez por día.

Un tag `runbook` opcional (un link a los pasos de rotación para ese recurso
puntual) se incluye como "próximo paso" clickeable en la alerta de Slack
cuando está presente. Otro "próximo paso" fijo, siempre presente, es el
comando de AWS CLI ya armado para actualizar el tag `expires` -- identificador
de recurso y sintaxis resueltos, solo falta reemplazar la fecha.
"""

import datetime as dt
import json
import os
import re
import time
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

TAG_EXPIRES = "expires"
TAG_ALERTED_FOR = "expires-alerted-for"
TAG_ALERTED_TIER = "expires-alerted-tier"
TAG_ALERTED_DATE = "expires-alerted-date"
TAG_RUNBOOK = "runbook"

TIERS = (30, 14, 7, 1)

# Título de Slack por tier -- así "ya venció" no se ve igual que "vence en
# 30 días" a simple vista, sin tener que leer el cuerpo del mensaje.
ALERT_TITLES = {
    "malformed": ":warning: INVALID EXPIRATION TAG",
    "30": ":calendar: CREDENTIAL EXPIRING",
    "14": ":calendar: CREDENTIAL EXPIRING",
    "7": ":warning: CREDENTIAL EXPIRING SOON",
    "1": ":rotating_light: CREDENTIAL EXPIRING -- URGENT",
    "overdue": ":rotating_light: CREDENTIAL EXPIRED",
}
DEFAULT_ALERT_TITLE = ":warning: CREDENTIAL EXPIRATION"

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ENV_NAME = os.environ["ENV_NAME"]
ENV_BADGE = f"*[{ENV_NAME.strip().upper()}]*"

# total_max_attempts, no max_attempts: en un objeto Config max_attempts cuenta
# sólo los reintentos y excluye el request inicial. Acá son 5 en total.
# https://docs.aws.amazon.com/boto3/latest/guide/retries.html
BOTO_CONFIG = Config(retries={"mode": "standard", "total_max_attempts": 5})

tagging_client = boto3.client("resourcegroupstaggingapi", config=BOTO_CONFIG)
secretsmanager_client = boto3.client("secretsmanager", config=BOTO_CONFIG)
ssm_client = boto3.client("ssm", config=BOTO_CONFIG)
sns_client = boto3.client("sns", config=BOTO_CONFIG)

WRITE_RETRY_ERROR_CODES = frozenset({"TooManyUpdates"})
WRITE_MAX_ATTEMPTS = 3
WRITE_BACKOFF_BASE_SECONDS = 0.5


def get_tagged_resources() -> list[dict[str, Any]]:
    """Devuelve cada secret de Secrets Manager / parámetro SSM tageado con `expires`."""
    paginator = tagging_client.get_paginator("get_resources")
    resources = []
    for page in paginator.paginate(
        TagFilters=[{"Key": TAG_EXPIRES}],
        ResourceTypeFilters=["secretsmanager:secret", "ssm:parameter"],
    ):
        resources.extend(page["ResourceTagMappingList"])
    return resources


def parse_expires(raw: str) -> dt.date | None:
    """Parsea el valor del tag `expires`, devuelve None si no es YYYY-MM-DD."""
    try:
        return dt.date.fromisoformat(raw)
    except ValueError:
        return None


def most_urgent_tier(days_remaining: int) -> str | None:
    """Devuelve el tier más ajustado (como string) que satisface days_remaining.

    None si todavía falta más que el tier más amplio (30 días) -- o sea, si no
    hay nada para alertar sobre este recurso.
    """
    satisfied = [tier for tier in TIERS if days_remaining <= tier]
    return str(min(satisfied)) if satisfied else None


def arn_service(arn: str) -> str:
    """Devuelve el segmento de servicio de un ARN (ej. "secretsmanager", "ssm")."""
    return arn.split(":")[2]


def ssm_parameter_name(arn: str) -> str:
    """Nombre del parámetro SSM (con "/" inicial) a partir de su ARN.

    SSM parameter ARNs tienen la forma arn:aws:ssm:region:account:parameter/name
    -- las APIs de SSM piden el nombre, no el ARN.
    """
    return "/" + arn.split(":parameter/", 1)[1]


# Secrets Manager le agrega al nombre un guión y seis caracteres random al
# armar el ARN; el nombre "amigable" -- el que muestra la consola y el que
# aceptan las APIs -- es ese sufijo removido.
SECRET_ARN_SUFFIX = re.compile(r"-[A-Za-z0-9]{6}$")


def secret_name(arn: str) -> str:
    """Nombre amigable de un secret de Secrets Manager a partir de su ARN."""
    return SECRET_ARN_SUFFIX.sub("", arn.split(":secret:", 1)[1])


RESOURCE_KIND_BY_SERVICE = {
    "secretsmanager": "Secrets Manager secret",
    "ssm": "SSM parameter",
}


def resource_name(arn: str) -> str:
    """Nombre del recurso, para identificarlo en la alerta sin mandar el ARN.

    El ARN arrastra partición, región y --sobre todo-- el account ID hasta un
    canal de Slack. El nombre alcanza para saber qué recurso rotar, y es
    además lo que piden los comandos de rotate_command().
    """
    service = arn_service(arn)
    if service == "secretsmanager":
        return secret_name(arn)
    if service == "ssm":
        return ssm_parameter_name(arn)
    # Los ResourceTypeFilters del escaneo sólo dejan pasar esos dos; si
    # apareciera otro, el último tramo del ARN sigue sin incluir la cuenta.
    return arn.split(":", 5)[-1]


def format_resource_header(arn: str) -> str:
    """Línea de Slack con el badge de entorno, el tipo de recurso, y el nombre en code span.

    El code span (backticks) alrededor del nombre lo deja en monoespaciado y
    marca dónde empieza y termina -- los nombres de secret y de parámetro
    admiten "/", "." y "-", que Slack podría comerse como formato.
    """
    kind = RESOURCE_KIND_BY_SERVICE.get(arn_service(arn), "resource")
    return f"{ENV_BADGE} *{kind}* `{resource_name(arn)}`"


def rotate_command(arn: str) -> str:
    """Comando de AWS CLI ya armado para actualizar el tag `expires` de `arn`.

    Solo falta reemplazar la fecha -- identificador de recurso y sintaxis del
    comando ya resueltos, para no depender de que alguien los reconstruya de
    memoria al rotar.
    """
    service = arn_service(arn)
    if service == "secretsmanager":
        return (
            f'aws secretsmanager tag-resource --secret-id "{secret_name(arn)}" '
            "--tags Key=expires,Value=YYYY-MM-DD"
        )
    if service == "ssm":
        return (
            "aws ssm add-tags-to-resource --resource-type Parameter "
            f'--resource-id "{ssm_parameter_name(arn)}" '
            "--tags Key=expires,Value=YYYY-MM-DD"
        )
    msg = f"Unexpected resource type in ARN: {arn}"
    raise ValueError(msg)


def evaluate(
    arn: str,
    tags: dict[str, str],
    today: dt.date,
) -> tuple[str, str, str, str | None] | None:
    """Decide si `arn` necesita una alerta nueva.

    Devuelve (message, new_alerted_for, new_alerted_tier, runbook_url), o
    None si no hay nada nuevo para enviar en esta ejecución.

    Cada tier (30/14/7/1) alerta una sola vez, igual que un `expires`
    malformado; "overdue" sí se repite, pero como máximo una vez por día
    calendario UTC. Cambiar el valor de `expires` arranca un ciclo nuevo y
    vuelve a habilitar todo.
    """
    raw_expires = tags[TAG_EXPIRES]
    fresh_cycle = tags.get(TAG_ALERTED_FOR) != raw_expires
    previous_tier = None if fresh_cycle else tags.get(TAG_ALERTED_TIER)
    already_alerted_today = tags.get(TAG_ALERTED_DATE) == today.isoformat()
    runbook_url = tags.get(TAG_RUNBOOK)

    header = format_resource_header(arn)

    expires_date = parse_expires(raw_expires)
    if expires_date is None:
        if fresh_cycle:
            message = (
                f"{header}\n"
                f"Invalid `expires` tag: {raw_expires!r} (expected YYYY-MM-DD)."
            )
            return message, raw_expires, "malformed", runbook_url
        return None

    days_remaining = (expires_date - today).days

    if days_remaining < 0:
        if previous_tier == "overdue" and already_alerted_today:
            return None
        message = (
            f"{header}\n"
            f"EXPIRED {-days_remaining}d ago (expires={raw_expires}) "
            "-- rotate immediately."
        )
        return message, raw_expires, "overdue", runbook_url

    tier = most_urgent_tier(days_remaining)
    if tier is None:
        # Todavía no toca alertar -- write_tags() nunca se ejecuta, así que una
        # rotación que empuja `expires` lejos deja obsoletos en el recurso
        # los tags viejos de alerted-for/tier/date, hasta que la próxima
        # alerta real los sobreescriba. Inofensivo: fresh_cycle (arriba) solo
        # compara contra el `expires` actual, así que no lo engañan los
        # valores obsoletos.
        return None

    if previous_tier is not None:
        try:
            if int(tier) >= int(previous_tier):
                return None
        except ValueError:
            pass  # previous tier tag was corrupted -- treat as never-alerted

    message = (
        f"{header}\n"
        f"Expires in {days_remaining}d (expires={raw_expires})."
    )
    return message, raw_expires, tier, runbook_url


def put_tracking_tags(arn: str, new_tags: list[dict[str, str]]) -> None:
    """Un solo intento de escribir `new_tags` sobre `arn`, vía la API nativa del servicio."""
    service = arn_service(arn)
    if service == "secretsmanager":
        secretsmanager_client.tag_resource(SecretId=arn, Tags=new_tags)
    elif service == "ssm":
        ssm_client.add_tags_to_resource(
            ResourceType="Parameter",
            ResourceId=ssm_parameter_name(arn),
            Tags=new_tags,
        )
    else:
        msg = f"Unexpected resource type in ARN: {arn}"
        raise ValueError(msg)


def write_tags(arn: str, alerted_for: str, alerted_tier: str, today: dt.date) -> None:
    """Escribe de vuelta sobre `arn` los tags de tracking (alerted_for/tier/date).

    Reintenta ante los errores de WRITE_RETRY_ERROR_CODES. El reintento va acá
    y no a nivel de invocación (la Lambda tiene `retry_attempts=0`) porque este
    es el único trozo idempotente: escribir los mismos tags dos veces deja el
    recurso igual, mientras que reintentar la invocación entera volvería a
    ejecutar publish_alert() y mandaría el mensaje a Slack de nuevo.

    Importa que funcione: process_resource() alerta *antes* de llegar acá, así
    que un write que falla deja el recurso avisado pero sin marcar -- y el
    escaneo de mañana lo vuelve a alertar.
    """
    new_tags = [
        {"Key": TAG_ALERTED_FOR, "Value": alerted_for},
        {"Key": TAG_ALERTED_TIER, "Value": alerted_tier},
        {"Key": TAG_ALERTED_DATE, "Value": today.isoformat()},
    ]

    for attempt in range(1, WRITE_MAX_ATTEMPTS + 1):
        try:
            put_tracking_tags(arn, new_tags)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in WRITE_RETRY_ERROR_CODES or attempt == WRITE_MAX_ATTEMPTS:
                raise
            delay = WRITE_BACKOFF_BASE_SECONDS * 2 ** (attempt - 1)
            print(
                f"write_tags: {code} on {arn} "
                f"(attempt {attempt}/{WRITE_MAX_ATTEMPTS}), retrying in {delay:.1f}s",
            )
            time.sleep(delay)
        else:
            return


def publish_alert(message: str, runbook_url: str | None, command: str, tier: str) -> None:
    """Publica una alerta como notificación custom de AWS Chatbot.

    El título varía según `tier` (ver ALERT_TITLES) -- "ya venció" tiene que
    distinguirse de "vence en 30 días" sin tener que abrir el mensaje.

    Ver: https://docs.aws.amazon.com/chatbot/latest/adminguide/custom-notifs.html
    """
    content: dict[str, Any] = {
        "textType": "client-markdown",
        "title": ALERT_TITLES.get(tier, DEFAULT_ALERT_TITLE),
        "description": message,
    }
    next_steps = []
    if runbook_url:
        next_steps.append(f"<{runbook_url}|Runbook>")
    next_steps.append(f"Update the tag: `{command}`")
    content["nextSteps"] = next_steps
    payload = {"version": "1.0", "source": "custom", "content": content}
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=json.dumps(payload),
    )


def process_resource(resource: dict[str, Any], today: dt.date) -> bool:
    """Evalúa y, si hace falta, alerta sobre un único recurso tageado.

    Devuelve True si se envió una alerta. Deja propagar cualquier error --de la
    publicación a SNS o de la escritura de tags--: lambda_handler los atrapa
    por recurso, así que uno roto no frena el escaneo de los demás.
    """
    arn = resource["ResourceARN"]
    tags = {t["Key"]: t["Value"] for t in resource["Tags"]}

    result = evaluate(arn, tags, today)
    if result is None:
        return False

    message, new_alerted_for, new_alerted_tier, runbook_url = result
    command = rotate_command(arn)
    print(
        f"{arn} -- "
        + message
        + f" Update: {command}"
        + (f" Runbook: {runbook_url}" if runbook_url else ""),
    )
    publish_alert(message, runbook_url, command, new_alerted_tier)
    write_tags(arn, new_alerted_for, new_alerted_tier, today)
    return True


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, int]:
    """Escanea recursos tageados con expires y alerta sobre tiers recién cruzados.

    Devuelve {"resources_scanned": N, "alerts_sent": N}.

    Un recurso que falla no corta el escaneo: se aísla, se loguea, y el resto
    sigue. Pero si al menos uno falló, la función termina levantando
    RuntimeError, a propósito. Una invocación que devuelve OK con recursos sin
    procesar no publica nada en la métrica Errors, y la alarma de errores del
    stack --que rutea al mismo canal de Slack-- nunca se enteraría.
    """
    print("## Event ##")
    print(event)
    print(f"Request ID: {context.aws_request_id}")

    today = dt.datetime.now(tz=dt.UTC).date()
    resources = get_tagged_resources()
    print(f"Found {len(resources)} resource(s) tagged `{TAG_EXPIRES}`.")

    alerts_sent = 0
    failures = []
    for resource in resources:
        arn = resource["ResourceARN"]
        try:
            if process_resource(resource, today):
                alerts_sent += 1
        except Exception as exc:  # noqa: BLE001 -- aísla un recurso con problemas del resto
            print(f"Failed to process {arn}: {exc}")
            failures.append(arn)

    print(
        f"Sent {alerts_sent} alert(s); {len(failures)} failure(s); "
        f"{len(resources)} resource(s) scanned.",
    )
    if failures:
        msg = f"Failed to process {len(failures)} resource(s): {failures}"
        raise RuntimeError(msg)

    return {"resources_scanned": len(resources), "alerts_sent": alerts_sent}
