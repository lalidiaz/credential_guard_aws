#!/usr/bin/env python3
import os

import aws_cdk as cdk

from stacks.credential_guard_stack import CredentialGuardStack
from stacks.demo_resources_stack import DemoResourcesStack

app = cdk.App()

# La región está fija en us-east-1
CHATBOT_METRICS_REGION = "us-east-1"

env = cdk.Environment(
    account=os.getenv("CDK_DEFAULT_ACCOUNT"),
    region=CHATBOT_METRICS_REGION,
)

slack_workspace_id = os.getenv("SLACK_WORKSPACE_ID")
slack_channel_id = os.getenv("SLACK_CHANNEL_ID")
if not slack_workspace_id or not slack_channel_id:
    raise SystemExit(
        "Missing required environment variables. Set them before deploying:\n"
        "  export SLACK_WORKSPACE_ID=T0XXXXXXX\n"
        "  export SLACK_CHANNEL_ID=C0XXXXXXX\n"
        "(see .env.example) See README.md for how to obtain these from the "
        "AWS Chatbot console.",
    )

env_name = os.getenv("ENV_NAME", "demo")

guard = CredentialGuardStack(
    app,
    "CredentialGuardStack",
    env=env,
    slack_workspace_id=slack_workspace_id,
    slack_channel_id=slack_channel_id,
    env_name=env_name,
    schedule_hour="10",
    schedule_minute="0",
    schedule_time_zone=cdk.TimeZone.AMERICA_MONTEVIDEO,
)

if os.getenv("DEMO_RESOURCES") == "true":
    demo = DemoResourcesStack(
        app,
        "CredentialGuardDemoResourcesStack",
        env=env,
        env_name=env_name,
    )
    # El escaneo inicial que se ejecuta dentro de CredentialGuardStack tiene que
    # pasar ANTES de que existan los recursos de demo. Si el orden se da al
    # revés, ese escaneo consume las tres alertas de la demo (el scanner es
    # idempotente: los tags expires-alerted-* hacen que cada tier alerte una
    # sola vez) y la invocación manual en cámara devuelve alerts_sent=0 con
    # Slack en silencio. Sin esta dependencia el orden entre dos stacks sin
    # relación no está garantizado -- hoy funciona sólo porque
    # CredentialGuardStack se declara primero, y `cdk deploy --all` con
    # concurrencia podría desplegarlos en paralelo.
    demo.add_stack_dependency(guard)

app.synth()
