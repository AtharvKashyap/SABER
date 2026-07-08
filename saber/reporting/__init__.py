"""Reporting package for SABER.

Reporters/exporters convert normalized mission evidence into portable report
formats such as JSON, PDF, and XLSX.

Reporting consumes observations/findings. It does not run tools, parse raw tool
output, call agents, or mutate mission plans.

Typical flow:

    ParserResult + MissionRunResult -> ReportDocument -> JSON/XLSX/PDF
"""

__all__: list[str] = []
