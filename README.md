# AI Accountability Infrastructure

A framework for ensuring accountability and transparency in AI systems through cryptographic proofs and logging.

## Project Structure

```
.
├── config/               # Configuration files
├── data/                 # Data files and fixtures
├── docs/                 # Documentation
├── scripts/              # Utility scripts
├── src/                  # Source code
│   └── ai_trust/        # Main package
│       ├── api/         # API endpoints and routes
│       ├── cli/         # Command-line interface
│       ├── core/        # Core functionality
│       ├── models/      # Data models and schemas
│       ├── services/    # Business logic and services
│       └── utils/       # Utility functions
├── tests/               # Test files
│   ├── integration/     # Integration tests
│   ├── performance/     # Performance tests
│   └── unit/            # Unit tests
└── tools/               # Development tools
```

## Getting Started

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/ai-accountability-infrastructure.git
   cd ai-accountability-infrastructure
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the package in development mode:
   ```bash
   pip install -e .[dev]
   ```

## Usage

### Running the API Server

```bash
uvicorn ai_trust.core.app:create_app --reload
```

### Running Tests

```bash
# Run all tests
pytest

# Run unit tests only
pytest tests/unit

# Run with coverage report
pytest --cov=ai_trust tests/
```

## Development

### Code Style

This project uses:
- Black for code formatting
- isort for import sorting
- mypy for static type checking
- flake8 for linting

Run the following commands before committing:

```bash
black .
isort .
flake8
mypy .
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
