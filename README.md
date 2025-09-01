# AI Trust Infrastructure

A framework for transparent and verifiable AI operations.

## Features

- Cryptographic receipts for AI model outputs
- Transparency logging
- Witness services
- API gateway for integration

## Installation

```bash
# Install with pip
pip install -e '.[server,crypto]'

# Or with all development dependencies
pip install -e '.[dev,server,crypto]'
```

## Development

Set up pre-commit hooks:

```bash
pre-commit install
```

Run tests:

```bash
pytest
```

## License

Apache 2.0
