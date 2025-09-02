# Contributing to AI Accountability

Thank you for your interest in contributing to the AI Accountability project! We welcome contributions from everyone, whether you're a developer, researcher, or just someone who cares about AI accountability.

## Ways to Contribute

There are many ways to contribute to this project:

1. **Code Contributions**: Implement new features, fix bugs, or improve documentation
2. **Testing**: Test the software and report any issues you find
3. **Documentation**: Improve documentation, add examples, or write tutorials
4. **Feedback**: Share your ideas and feedback on the project
5. **Spread the Word**: Tell others about the project

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally
   ```bash
   git clone https://github.com/your-username/ai-accountability.git
   cd ai-accountability
   ```
3. **Set up** the development environment
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```
4. **Create a branch** for your changes
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

1. **Write code** and **add tests** for your changes
2. **Run tests** to make sure everything works
   ```bash
   pytest
   ```
3. **Format your code** using Black
   ```bash
   black .
   ```
4. **Check types** with mypy
   ```bash
   mypy .
   ```
5. **Commit your changes** with a descriptive commit message
   ```bash
   git add .
   git commit -m "Add your descriptive commit message here"
   ```
6. **Push** to your fork
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Open a Pull Request** on GitHub

## Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) for Python code
- Use [Black](https://github.com/psf/black) for code formatting
- Use type hints for all function signatures and variables
- Write docstrings for all public functions, classes, and methods
- Keep lines under 100 characters

## Testing

- Write tests for all new functionality
- Run tests before submitting a PR
   ```bash
   pytest
   ```
- Aim for good test coverage (run `pytest --cov` to check)

## Documentation

- Update documentation when adding new features or changing behavior
- Keep docstrings up to date
- Add examples where helpful

## Reporting Issues

When reporting issues, please include:

1. A clear description of the issue
2. Steps to reproduce the issue
3. Expected behavior
4. Actual behavior
5. Any relevant error messages or logs
6. Your environment (OS, Python version, etc.)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).

## Getting Help

If you have questions or need help, please open an issue on GitHub or join our community forum.
