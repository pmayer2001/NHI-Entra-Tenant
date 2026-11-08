"""Mock "Sensitive Records" resource API (ADR-004, ADR-009).

The resource, not Entra, decides what data a caller sees: Entra issues a token
listing the caller's app roles, and this service maps each role to the fields
it may read, redacting the rest.
"""
