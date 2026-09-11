"""Stack solo para demo: crea un secret y dos parámetros tageados que alertan al instante.

No es parte del diseño con forma de producción (CredentialGuardStack). Existe
únicamente para que una demo grabada tenga algo para escanear apenas se
invoca la Lambda -- no afecta al stack real.
"""

import datetime as dt

from aws_cdk import SecretValue, Stack, Tags, aws_secretsmanager as secretsmanager, aws_ssm as ssm
from constructs import Construct


class DemoResourcesStack(Stack):
    """Un secret + dos parámetros tageados para ejercitar cada camino de alerta una vez."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        env_name: str = "demo",
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        today = dt.datetime.now(tz=dt.UTC).date()

        # Secrets Manager: dentro del tier de 7 días, con runbook. Cifrado
        # real con KMS -- SecretValue.unsafe_plain_text es la forma que
        # documenta CDK para valores placeholder de testing/demo (el valor
        # queda visible en el template sintetizado, por eso el nombre).
        expiring_soon = secretsmanager.Secret(
            self,
            "DemoExpiringSoonSecret",
            secret_name=f"{env_name}/credential-expiration/expiring-soon",
            description="Demo secret: within the 7-day alert tier.",
            secret_string_value=SecretValue.unsafe_plain_text(
                "placeholder-value-not-a-real-secret",
            ),
        )
        Tags.of(expiring_soon).add("expires", str(today + dt.timedelta(days=5)))
        Tags.of(expiring_soon).add(
            "runbook",
            "https://example.com/runbook/rotate-demo-credential",
        )

        # SSM Parameter Store (gratis, tier Standard) para los otros dos.
        overdue = ssm.StringParameter(
            self,
            "DemoOverdueParam",
            parameter_name=f"/{env_name}/credential-expiration/overdue",
            string_value="placeholder-value-not-a-real-secret",
            description="Demo parameter: already past its expires date.",
        )
        Tags.of(overdue).add("expires", str(today - dt.timedelta(days=2)))

        malformed = ssm.StringParameter(
            self,
            "DemoMalformedParam",
            parameter_name=f"/{env_name}/credential-expiration/malformed",
            string_value="placeholder-value-not-a-real-secret",
            description="Demo parameter: an unparseable expires tag value.",
        )
        Tags.of(malformed).add("expires", "not-a-date")
