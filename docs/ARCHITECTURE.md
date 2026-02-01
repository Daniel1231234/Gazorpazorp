# Architecture

## Overview

Gazorpazorp is a multi-layered security gateway designed specifically for autonomous AI agents.

## Component Diagram

1. **Express Gateway**: Handles incoming HTTP requests and orchestrates the pipeline.
2. **Crypto Layer**: Verifies Ed25519 signatures.
3. **Semantic Layer**: Uses local LLMs to analyze intent.
4. **Policy Engine**: Evaluates risk scores against defined rule sets.
5. **Redis Store**: Manages persistence for keys, history, and metrics.
