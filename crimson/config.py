"""Crimson configuration — all settings via environment variables."""

import os


# Model
MODEL_ID = os.environ.get(
    "CRIMSON_MODEL_ID",
    "arn:aws:bedrock:us-east-1:651818016290:application-inference-profile/kzx60kroqtkq",
)

# Neo4j
NEO4J_URI = os.environ.get("NEO4J_URI", "")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")
NEO4J_DATABASE = os.environ.get("NEO4J_DATABASE", "neo4j")
NEO4J_READONLY_USER = os.environ.get("NEO4J_READONLY_USER", "")
NEO4J_READONLY_PASSWORD = os.environ.get("NEO4J_READONLY_PASSWORD", "")

# Datadog
DD_API_KEY = os.environ.get("DD_API_KEY", "")
DD_APP_KEY = os.environ.get("DD_APP_KEY", "")
DD_SITE = os.environ.get("DD_SITE", "datadoghq.com")

# Limits
MAX_ATTACKS = int(os.environ.get("CRIMSON_MAX_ATTACKS", "7"))
MAX_TURNS = int(os.environ.get("CRIMSON_MAX_TURNS", "8"))
TIMEOUT = int(os.environ.get("CRIMSON_TIMEOUT", "900"))

# Artifacts
ARTIFACT_DIR = os.environ.get("CRIMSON_ARTIFACT_DIR", "./crimson_runs/")
