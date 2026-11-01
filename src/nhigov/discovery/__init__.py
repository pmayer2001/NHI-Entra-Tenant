"""Discovery (CLAUDE.md §7): inventory every NHI in the tenant and flag problems.

Read-only by construction: it runs as nhigov-scanner, which holds no write
permission, so a bug here can report something wrong but can't change anything.
"""
