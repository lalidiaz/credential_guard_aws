# CredentialGuardStack

## Resumen

Escanea cada secret de Secrets Manager y cada parámetro de SSM tageado con
`expires=YYYY-MM-DD`, y publica una alerta escalonada en Slack (30/14/7/1 días
antes del vencimiento) a medida que esa fecha se acerca, para que la credencial
se rote antes de que rompa algo. Es region-wide, no está atado a una app
puntual: tagear el recurso es el único paso de integración necesario, sin
cambios de código.

Construido con AWS CDK (Python):

- `aws_cdk.aws_lambda` — la Lambda de escaneo/alerta (`lambda/credential_scanner.py`)
- `aws_cdk.aws_scheduler` — schedule diario de EventBridge Scheduler (cron,
con zona horaria explícita)
- `aws_cdk.aws_sns` — el topic de alertas
- `aws_cdk.aws_chatbot.SlackChannelConfiguration` — entrega a Slack vía AWS
Chatbot (ahora rebautizado **Amazon Q Developer in chat applications**)
- `aws_cdk.aws_cloudwatch` — tres alarmas de auto-monitoreo, ruteadas al
mismo canal de Slack: errores de la propia Lambda, el schedule diario que no
llega a invocarla (un día entero sin ningún dato de `Invocations` --
el schedule deshabilitado, un permiso roto, etc.), y fallas de entrega de
Amazon Q Developer in chat applications hacia Slack (`MessageDeliveryFailure`)

## Arquitectura

El recorrido de una alerta:

```
EventBridge Scheduler → Lambda → SNS → Amazon Q Developer in chat applications → Slack
```

Un detalle central de ese recorrido: **la Lambda nunca llama a la API de
Slack**. Solo publica al topic de SNS. Amazon Q Developer in chat
applications está suscripto a ese topic y es quien reenvía al canal.

## Cómo funciona

- **Trigger**: EventBridge Scheduler dispara la Lambda a diario, por defecto
a las 10:00 de Montevideo. La hora sale de `schedule_hour` /
`schedule_minute` / `schedule_time_zone`, tres parámetros propios de este
stack (`stacks/credential_guard_stack.py`), que se pasan a la cron de
Scheduler. La zona se declara a propósito en vez de hardcodear una hora UTC:
así el schedule significa "10 de la mañana para quien rota la credencial" aun
si el país vuelve a mover su política horaria. En el template sintetizado se
ve como `ScheduleExpressionTimezone: America/Montevideo`. Además del schedule, cada
`cdk deploy` dispara un escaneo en el momento (`triggers.Trigger` en
`stacks/credential_guard_stack.py`), así que desplegar ya puede publicar
alertas en Slack: sin esa primera ejecución la métrica `Invocations` todavía no
existe y la alarma de "no hubo invocaciones" se dispararía en falso apenas se crea.
- **Descubrimiento**: `get_tagged_resources()` llama a la Resource Groups
Tagging API (`tag:GetResources`), no a las APIs de listado propias de
Secrets Manager o SSM. Esto es lo que hace que el escaneo sea region-wide.
- **Decisión** (`evaluate()`): el tag `expires` de cada recurso se clasifica
como malformado, vencido, o dentro de un tier de 30/14/7/1 días. Tres tags
de tracking que la Lambda escribe de vuelta (`expires-alerted-for`,
`expires-alerted-tier`, `expires-alerted-date`) evitan re-alertar en el
mismo tier todos los días; actualizar `expires` después de una rotación
resetea el ciclo. Una vez vencida, la alerta sí se repite -- pero como
máximo una vez por día calendario (UTC), gracias a `expires-alerted-date`;
sin ese tag, invocar la función más de una vez el mismo día la manda de
nuevo cada vez.
- **Entrega**: la Lambda no llama a la API de Slack directamente — publica
cada alerta al topic de SNS (`sns_client.publish()` en `publish_alert()`,
`lambda/credential_scanner.py`) usando el schema de
[notificación custom de AWS
Chatbot](https://docs.aws.amazon.com/chatbot/latest/adminguide/custom-notifs.html)
(`version`/`source`/`content`, con `title`, `description`, `nextSteps`). Ese
topic está registrado como `notification_topics` del
`SlackChannelConfiguration` (`stacks/credential_guard_stack.py`), así que
**Amazon Q Developer in chat applications** — nombre actual de AWS Chatbot,
[renombrado el 19-02-2025](https://docs.aws.amazon.com/chatbot/latest/adminguide/service-rename.html)
— queda suscripto a ese topic, recibe cada mensaje, lo formatea y lo reenvía
al canal de Slack ya autorizado. No hay ningún llamado directo a la API de
Slack en el código: todo el reenvío lo hace ese servicio administrado por
AWS. El título varía según la severidad (`:calendar:` para 30/14 días,
`:warning:` para 7,
`:rotating_light:` para 1 día/vencido), el cuerpo arranca con un badge de
entorno en mayúsculas (`ENV_NAME`, sin depender de que alguien le meta un
emoji a mano), y los próximos pasos incluyen el link al `runbook` (si el
recurso tiene ese tag) más un comando de AWS CLI ya armado para actualizar
`expires` — solo hay que pegarlo y cambiar la fecha.
- **Permisos**: deliberadamente mínimos — `tag:GetResources` (tiene que ser
`*`, la Tagging API no tiene scoping a nivel de recurso),
`secretsmanager:TagResource` / `ssm:AddTagsToResource` (solo para escribir
de vuelta los tres tags de tracking), y `sns:Publish` (vía
`topic.grant_publish()`). Notablemente **sin** `GetSecretValue`/`GetParameter`
— esta Lambda nunca lee el valor real de la credencial.
- **Rol del canal de Slack**: en `SlackChannelConfiguration`, `role` y
`guardrail_policies` son dos knobs independientes -- pasar un rol propio
**no** alcanza por sí solo para evitar el guardrail default
(`AdministratorAccess`); hay que setear `guardrail_policies` aparte, aun
habiendo pasado tu propio rol. Este stack setea los dos a propósito: un rol
acotado a la política ["Notification Permissions"
documentada por AWS](https://docs.aws.amazon.com/chatbot/latest/adminguide/chatbot-iam-policies.html#read-only-notifications-policy)
(`cloudwatch:Describe*/Get*/List*`), más una guardrail `ReadOnlyAccess` — el
mínimo que documenta AWS para un canal que solo recibe notificaciones.

## Costo

Ninguno de los servicios de "Amazon Q" que usa este proyecto tiene costo de
licencia. **Amazon Q Developer in chat applications** (usado acá vía
`aws_chatbot.SlackChannelConfiguration`) es el nombre actual de **AWS
Chatbot** — mismo servicio, [renombrado el
19-02-2025](https://docs.aws.amazon.com/chatbot/latest/adminguide/service-rename.html).
Las features que usa este stack (entrega de notificaciones vía SNS) son
las **no generativas**.

Lo único que este stack factura en la práctica son los recursos subyacentes
ya listados arriba — 1 invocación de Lambda por día, unas pocas
publicaciones a SNS, 3 alarmas de CloudWatch, el log group de la Lambda y el
que crea Amazon Q Developer in chat applications para sus propios logs de
error (`logging_level=ERROR` en el `SlackChannelConfiguration`).

## Prerequisito: el CLI de CDK

El comando `cdk` (`cdk bootstrap`, `cdk deploy`) es un paquete de npm aparte y
necesita Node.js -- no sale de `requirements.txt`. Ahí está `aws-cdk-lib`, que
es la librería de constructs que importa `app.py`: son dos cosas distintas, y
hasta las versiones van por series separadas.

```bash
npm install -g aws-cdk
```

## Prerequisito: autorizar tu workspace de Slack (manual, una sola vez)

CloudFormation/CDK **no puede** hacer el handshake OAuth con Slack — es un
paso solo-consola, una vez por workspace, según el [tutorial oficial de
Slack](https://docs.aws.amazon.com/chatbot/latest/adminguide/slack-setup.html).

No hace falta terminar de configurar un canal desde la consola — una vez
autorizado el workspace, `cdk deploy` crea el recurso de configuración del
canal por su cuenta.

## Deploy

Los valores de Slack se leen desde variables de entorno (no se commitean, no
van por contexto de CDK) porque este es un repo público — ver `.env.example`.

La cuenta de AWS (`CDK_DEFAULT_ACCOUNT`, usada en `app.py`) **no hace falta
exportarla a mano** — la completa automáticamente el propio CDK CLI a partir
de tus credenciales activas (perfil default, `--profile`, SSO) antes de
ejecutar `app.py`. Alcanza con que `aws sts get-caller-identity` te devuelva la
cuenta correcta; si usás un perfil con nombre, exportá `AWS_PROFILE=tu-perfil`
(o pasá `--profile` a los comandos `cdk`) en vez de setear `CDK_DEFAULT_ACCOUNT`
vos misma.

La **región está fija en `us-east-1`** en `app.py`.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env   # completar SLACK_WORKSPACE_ID / SLACK_CHANNEL_ID
set -a && source .env && set +a

# Bootstrap: Una sola vez por cuenta/región.
# https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html
cdk bootstrap

cdk deploy CredentialGuardStack
```

## Probar con datos de demo (opcional)

Para ejercitar los tres caminos de alerta (por vencer, vencido, tag malformado) en el mismo deploy -- sin esperar a que una credencial real se acerque a su vencimiento ni tagear algo a mano -- seteá `DEMO_RESOURCES=true`
en tu `.env` (ver `.env.example`) y deployá también la stack de demo:

```bash
cdk deploy CredentialGuardStack CredentialGuardDemoResourcesStack
```

Esto crea, ya pre-tageado, vía `stacks/demo_resources_stack.py`:

- Un secret de Secrets Manager dentro del tier de 7 días, con tag `runbook`.
- Un parámetro SSM ya vencido.
- Un parámetro SSM con un tag `expires` no parseable.

El escaneo que se ejecuta durante el `cdk deploy` pasa *antes* de que existan estos
recursos (`app.py` fuerza ese orden a propósito, para no consumir las alertas
de la demo), así que las tres quedan sin usar. Para verlas llegar a Slack,
invocá la Lambda a mano. El nombre de la función sale como output
`ScannerFunctionName` del deploy, así que lo podés levantar directo del stack:

```bash
export SCANNER_FN=$(aws cloudformation describe-stacks \
  --stack-name CredentialGuardStack \
  --query "Stacks[0].Outputs[?OutputKey=='ScannerFunctionName'].OutputValue" \
  --output text)

aws lambda invoke --function-name "$SCANNER_FN" --payload '{}' /dev/stdout
```

No es parte del diseño de producción (`CredentialGuardStack`) -- es solo para tener algo que escanear apenas se invoca la Lambda, por ejemplo al grabar una demo. Para evitar gastos, destruí el stack aparte cuando termines -- con
`DEMO_RESOURCES=true` todavía seteado, porque sin esa variable `app.py` no
llega a crear la stack y `cdk destroy` no la encuentra:

```bash
cdk destroy CredentialGuardDemoResourcesStack
```

## Onboarding de una credencial real (sin cambios de código)

```bash
aws ssm add-tags-to-resource \
  --resource-type Parameter \
  --resource-id "/prod/third-party-app/MY_PAT" \
  --tags Key=expires,Value=2026-10-01 Key=runbook,Value="https://<my-docs-link-here>.com"
```

(La misma idea para un secret de Secrets Manager vía
`aws secretsmanager tag-resource`.) El próximo escaneo diario lo detecta
automáticamente.

## Rotar una credencial una vez alertada

Tagear es solo metadata — rotar el valor real y reiniciar lo que sea que lo
consume son pasos manuales separados que este stack no automatiza:

1. Generar el nuevo valor de la credencial.
2. Actualizar el **valor** del secret/parámetro si utilizás Secrets Manager o Parameter Store para guardar el valor (no solo sus tags).
3. Reiniciar el servicio que lee ese valor. Por ejemplo, una tarea de ECS que usa `ecs.Secret.from_ssm_parameter(...)` resuelve el valor solo al arrancar el contenedor — una tarea en ejecución nunca lo va a levantar sola.
4. Actualizar el tag `expires` con la nueva fecha de vencimiento — esto resetea el ciclo de alertas; si te lo salteás, el tracking del tier viejo sigue vigente para la fecha nueva. Cada alerta de Slack ya trae este comando armado (con el identificador del recurso resuelto) como "próximo paso" — solo hay que pegarlo y reemplazar la fecha.

