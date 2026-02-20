"""Neo4j connection management with context-manager support."""

from __future__ import annotations

import logging

from neo4j import GraphDatabase

from crimson import config

logger = logging.getLogger(__name__)


class Neo4jConnection:
    """Manages a Neo4j driver, sessions, and query execution."""

    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
        database: str | None = None,
    ):
        self.uri = uri or config.NEO4J_URI
        self.user = user or config.NEO4J_USER
        self.password = password or config.NEO4J_PASSWORD
        self.database = database or config.NEO4J_DATABASE
        self.driver = None

    # -- lifecycle -------------------------------------------------------------

    def connect(self) -> "Neo4jConnection":
        self.driver = GraphDatabase.driver(
            self.uri,
            auth=(self.user, self.password),
            max_connection_pool_size=50,
            connection_acquisition_timeout=60,
        )
        self.driver.verify_connectivity()
        logger.info("Connected to Neo4j at %s", self.uri)
        return self

    def close(self) -> None:
        if self.driver:
            self.driver.close()

    def __enter__(self) -> "Neo4jConnection":
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # -- query helpers ---------------------------------------------------------

    def execute(self, query: str, **params):
        """Execute a Cypher query and return (records, summary)."""
        records, summary, _keys = self.driver.execute_query(
            query, parameters_=params, database_=self.database
        )
        return records, summary

    def execute_write(self, query: str, **params):
        """Execute a write query inside a managed write-transaction."""
        with self.driver.session(database=self.database) as session:
            result = session.execute_write(
                lambda tx: tx.run(query, **params).consume()
            )
            return result
