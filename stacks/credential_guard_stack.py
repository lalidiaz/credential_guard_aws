"""Stack de CDK: escaneo diario de credenciales tageadas con alertas escalonadas en Slack.

Escanea cada secret de Secrets Manager y cada parámetro de SSM en la cuenta/región
tageado con `expires=YYYY-MM-DD`, y publica una alerta en Slack (vía SNS + Amazon Q in Chat Apps (ex AWS Chatbot)
a medida que esa fecha se acerca. No está atado a una app puntual: cualquier
recurso tageado con `expires`, sin importar quién lo haya creado, se detecta
en el próximo escaneo diario sin cambios de código.
"""

from pathlib import Path

from aws_cdk import (
    ArnFormat,
    CfnOutput,
    Duration,
    Stack,
    TimeZone,
    aws_chatbot as chatbot,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cloudwatch_actions,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_scheduler as scheduler,
    aws_scheduler_targets as scheduler_targets,
    aws_sns as sns,
    triggers,
)
from constructs import Construct

# Code.from_asset() empaqueta un directorio, no un archivo suelto, así que el
# asset es lambda/ entero y el handler apunta al módulo credential_scanner
# que vive adentro.
LAMBDA_ASSET_DIR = Path(__file__).parent.parent / "lambda"


class CredentialGuardStack(Stack):
    """Escanea a diario secrets/parámetros tageados con `expires` y alerta en Slack.

    Las alertas se disparan a 30/14/7/1 días del vencimiento, a diario una vez
    vencida, y una vez para un valor `expires` malformado. Ver
    lambda/credential_scanner.py para la lógica de escaneo/alerta.

    Dos cosas más, además del schedule diario:

    - Cada `cdk deploy` dispara un escaneo en el momento (`triggers.Trigger`), o
      sea que desplegar ya puede publicar alertas en Slack.
    - Tres alarmas de CloudWatch monitorean al propio sistema y rutean al mismo
      canal: errores de la Lambda, un día sin invocaciones, y fallas de entrega
      de Amazon Q Developer in chat applications hacia Slack.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        slack_workspace_id: str,
        slack_channel_id: str,
        env_name: str = "demo",
        schedule_hour: str = "10",
        schedule_minute: str = "0",
        schedule_time_zone: TimeZone = TimeZone.AMERICA_MONTEVIDEO,
        **kwargs,
    ) -> None:
        """Construye el stack.

        :param slack_workspace_id: ID del workspace ya autorizado a mano en la
            consola -- CDK no puede hacer ese handshake de OAuth.
        :param slack_channel_id: ID del canal de Slack que recibe las alertas.
        :param env_name: Etiqueta de entorno. La Lambda la usa como badge al
            principio de cada mensaje.
        :param schedule_hour: Campo *hora* de la cron de EventBridge
            Scheduler, evaluado en `schedule_time_zone`. Es un string, no un
            int, así que acepta la sintaxis completa de cron ("10", "*/6",
            "1,13").
        :param schedule_minute: Ídem para el campo *minuto*.
        :param schedule_time_zone: Zona en la que Scheduler evalúa la cron.
            Se declara a propósito en vez de hardcodear una hora UTC: así el
            schedule significa "las 10 de la mañana del equipo que rota la
            credencial" y no una hora que habría que recalcular a mano si el
            país mueve su política horaria. No es hipotético -- Uruguay tuvo
            horario de verano hasta 2015 y lo derogó. Omitirlo haría que CDK
            use el default de Scheduler, que es UTC (`TimeZone.ETC_UTC`).
        """
        super().__init__(scope, construct_id, **kwargs)

        topic = sns.Topic(
            self,
            "CredentialGuardTopic",
            topic_name="credential-expiration-alerts",
            display_name="Credential expiration alerts",
        )

        # Rol IAM mínimo para el canal de Slack. Es la política "Notification
        # Permissions" documentada por la propia AWS -- la opción de menor
        # privilegio para un canal que solo recibe notificaciones de SNS y
        # nunca ejecuta comandos de chat.
        # https://docs.aws.amazon.com/chatbot/latest/adminguide/chatbot-iam-policies.html
        #
        # Nota: la API Reference de CDK documenta el default de
        # `guardrail_policies` como AdministratorAccess "if this is not set"
        # https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_chatbot.SlackChannelConfigurationProps.html
        chatbot_role = iam.Role(
            self,
            "ChatbotNotificationsRole",
            assumed_by=iam.ServicePrincipal("chatbot.amazonaws.com"),
            inline_policies={
                "NotificationsOnly": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "cloudwatch:Describe*",
                                "cloudwatch:Get*",
                                "cloudwatch:List*",
                            ],
                            resources=["*"],
                        ),
                    ],
                ),
            },
        )

        # slack_workspace_id solo se puede obtener autorizando el workspace
        # una vez, a mano, en la consola de Amazon Q Developer in Chat Apps
        # (CDK no puede hacer ese handshake de OAuth).
        slack_channel = chatbot.SlackChannelConfiguration(
            self,
            "CredentialGuardSlackChannel",
            slack_channel_configuration_name="credential-expiration-alerts",
            slack_workspace_id=slack_workspace_id,
            slack_channel_id=slack_channel_id,
            role=chatbot_role,
            guardrail_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess"),
            ],
            logging_level=chatbot.LoggingLevel.ERROR,
            notification_topics=[topic],
        )

        fn = lambda_.Function(
            self,
            "CredentialGuardLambda",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="credential_scanner.lambda_handler",
            code=lambda_.Code.from_asset(
                str(LAMBDA_ASSET_DIR),
                exclude=["__pycache__"],
            ),
            description=(
                "Scans expires-tagged Secrets Manager secrets and SSM "
                "parameters, alerting at 30/14/7/1 days before expiry."
            ),
            log_group=logs.LogGroup(
                self,
                "CredentialGuardLambdaLogs",
                retention=logs.RetentionDays.ONE_MONTH,
            ),
            environment={"SNS_TOPIC_ARN": topic.topic_arn, "ENV_NAME": env_name},
            timeout=Duration.minutes(2),
            memory_size=256,
            # EventBridge invoca de forma asíncrona, y ahí Lambda reintenta dos
            # veces más por default ante un error de la función. Como la alerta
            # se publica *antes* de escribir los tags de tracking, un recurso
            # cuyo write falle ya mandó su mensaje a Slack pero quedó sin tags
            # -- cada reintento lo vuelve a evaluar como ciclo nuevo y lo manda
            # de nuevo: hasta 3 mensajes idénticos por un solo recurso roto.
            # Acá el reintento no aporta nada: el escaneo es diario, y como los
            # tags no se escribieron, la ejecución de mañana lo alerta igual.
            # https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html
            retry_attempts=0,
        )

        fn.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["tag:GetResources"],
                resources=["*"],
            ),
        )

        # Solo escritura de los tags de tracking. Deliberadamente sin
        # GetSecretValue/GetParameter -- nunca lee el material
        # secreto, solo tags.
        fn.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["secretsmanager:TagResource"],
                resources=[
                    self.format_arn(
                        service="secretsmanager",
                        resource="secret",
                        resource_name="*",
                        arn_format=ArnFormat.COLON_RESOURCE_NAME,
                    ),
                ],
            ),
        )
        fn.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ssm:AddTagsToResource"],
                resources=[
                    self.format_arn(
                        service="ssm",
                        resource="parameter",
                        resource_name="*",
                        arn_format=ArnFormat.SLASH_RESOURCE_NAME,
                    ),
                ],
            ),
        )

        topic.grant_publish(fn)

        scheduler.Schedule(
            self,
            "CredentialGuardDailySchedule",
            description="Daily trigger for the credential-expiration scanner",
            schedule=scheduler.ScheduleExpression.cron(
                minute=schedule_minute,
                hour=schedule_hour,
                time_zone=schedule_time_zone,
            ),
            # retry_attempts=0 por el mismo motivo que en la Lambda: la alerta
            # se publica *antes* de escribir los tags de tracking, así que cada
            # reintento vuelve a mandar el mensaje a Slack. El default de
            # Scheduler es 185, no 0.
            target=scheduler_targets.LambdaInvoke(fn, retry_attempts=0),
        )

        # Una ejecución como parte del deploy. La métrica Invocations no existe
        # hasta que la función se ejecuta por primera vez -- Lambda publica métricas
        # recién "when your function finishes processing an event", así que una
        # función nunca invocada no reporta un 0, no reporta nada. Sin esta
        # ejecución, no_invocation_alarm (abajo) evalúa una ventana enteramente
        # vacía apenas se crea y, con treat_missing_data=BREACHING, pasa a
        # ALARM al minuto del deploy: una alerta falsa en Slack por cada
        # `cdk deploy`, hasta el primer disparo del schedule.
        # https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.triggers-readme.html
        #
        # execute_after fuerza a que el topic y el canal de Slack existan antes
        # de que esta invocación intente publicar. El escaneo es idempotente
        # (los tags expires-alerted-* son el estado), así que esta ejecución extra
        # no duplica mensajes con el escaneo programado del mismo día.
        triggers.Trigger(
            self,
            "CredentialGuardInitialScan",
            handler=fn,
            execute_after=[topic, slack_channel],
        )

        # Un scanner roto fallaría en silencio y anularía todo el
        # sistema de monitoreo -- por eso sus propios errores se rutean al
        # mismo canal.
        error_alarm = cloudwatch.Alarm(
            self,
            "CredentialGuardLambdaErrorsAlarm",
            alarm_name=f"{construct_id}-lambda-errors",
            metric=fn.metric_errors(period=Duration.days(1)),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=(
                cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD
            ),
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        error_alarm.add_alarm_action(cloudwatch_actions.SnsAction(topic))

        # Errors solo reporta un dato cuando una invocación realmente falla --
        # un día en que el schedule nunca disparó (EventBridge deshabilitado,
        # un permiso roto, etc.) se ve idéntico a un día limpio: cero datos en
        # ambos casos. error_alarm (arriba) no puede distinguir eso.
        # Invocations sí reporta cada invocación real, así que alarmar sobre
        # "muy pocas de esas" -- tratando los datos faltantes como breach, no
        # ignorándolos -- es lo que realmente detecta "el scanner no se ejecutó
        # hoy", en vez de solo "el scanner se ejecutó y falló".
        #
        # Como Sum(Invocations) nunca vale 0 (si el datapoint existe, vale >= 1),
        # el umbral acá es formal: el único camino a ALARM es el de datos
        # faltantes, o sea treat_missing_data.
        #
        # Dos períodos, no uno. La ventana por default es deslizante: con una
        # sola ventana de 24h, una ejecución que llega unos segundos más tarde
        # que la de ayer la deja vacía y dispara una alerta falsa.
        # https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarm-evaluation-window.html
        no_invocation_alarm = cloudwatch.Alarm(
            self,
            "CredentialGuardNoInvocationAlarm",
            alarm_name=f"{construct_id}-no-invocation",
            metric=fn.metric_invocations(period=Duration.days(1)),
            threshold=1,
            evaluation_periods=2,
            datapoints_to_alarm=2,
            comparison_operator=cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.BREACHING,
        )
        no_invocation_alarm.add_alarm_action(cloudwatch_actions.SnsAction(topic))

        # La Lambda puede ejecutarse sin errores y SNS puede publicar bien, y aun así
        # Amazon Q in Chat Apps puede fallar al reenviar el mensaje a Slack (permisos,
        # un evento no soportado) -- esa falla solo aparece en
        # esta métrica. Mismo argumento de blast-radius que error_alarm arriba: sin esto, ese modo
        # de falla queda en silencio.
        chatbot_delivery_alarm = cloudwatch.Alarm(
            self,
            "CredentialGuardChatbotDeliveryFailureAlarm",
            alarm_name=f"{construct_id}-chatbot-delivery-failures",
            metric=slack_channel.metric(
                "MessageDeliveryFailure",
                period=Duration.days(1),
                statistic="Sum",
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=(
                cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD
            ),
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        chatbot_delivery_alarm.add_alarm_action(cloudwatch_actions.SnsAction(topic))

        self.function_name = fn.function_name
        self.topic = topic

        CfnOutput(
            self,
            "ScannerFunctionName",
            value=fn.function_name,
            description=(
                "For a manual demo run: "
                "aws lambda invoke --function-name <value> --payload '{}' /dev/stdout"
            ),
        )
        CfnOutput(self, "AlertsTopicArn", value=topic.topic_arn)
