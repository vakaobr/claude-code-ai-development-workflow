---
name: medallion-lakehouse-pipelines
description: "Scaffold, validate, and optimize Bronze, Silver, and Gold layers of a Medallion Lakehouse pipeline."
model: sonnet
metadata:
  version: 1.0.0
  category: data-engineering
---

# Medallion Lakehouse Pipeline Architecture

## Goal
Design and configure structured, modular data lakehouse pipelines following Delta Lake/Lakehouse best practices (Bronze, Silver, Gold).

## When to Use
- When building batch or streaming data pipelines in Delta Lake, Spark, or Databricks.
- Implementing robust data quality checks and SCD Type 2 dimension mapping.

## When NOT to Use
- Simple SQLite databases or transactional SQL queries where datalake scaling is unnecessary.

## Authorization Check
- Verify read/write permissions on the target cloud storage buckets or Spark tables.

## Methodology
1. **Bronze Layer (Ingestion & History)**:
   - Store raw ingest data exactly as received (JSON, Parquet, CSV).
   - Implement date hierarchical partitioning (e.g., `adventureworks/YYYY/MM/DD/TableName.parquet`).
2. **Silver Layer (Cleaning & Enrichment)**:
   - Apply schema enforcement and evolution modes.
   - Perform technical validations: rename columns to standard format, handle NULLs, deduplicate records based on business keys.
3. **Gold Layer (Analytical & Dimension Models)**:
   - Assemble star schema (Fact and Dimension tables).
   - Generate Slowly Changing Dimensions (SCD Type 2) scripts, generating record hash keys to compare state transitions and maintain history.

## Output Format
Generate PySpark, dbt, or Delta Live Tables scripts:
- Schema parameters configuration.
- Delta merger logic for Silver-to-Gold promotion.

## Quality Check
- Verify that Bronze contains untouched, historic raw data.
- Ensure that Silver cleans data based on a metadata configuration catalog.
- Verify SCD Type 2 logic is tested against empty, updated, and deleted rows.

## Common Issues
- Small file performance bottleneck: trigger automatic optimization compact steps (`OPTIMIZE table ZORDER BY business_key`).
