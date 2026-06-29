# Contributing to Automatic Recon Tool

Thank you for your interest in contributing! This project welcomes contributions from the community.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/automatic-recon-tool.git
   cd automatic-recon-tool
   ```
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Set up configuration**:
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```
5. **Run the application**:
   ```bash
   python automatic_recon_gui.py
   ```

## Development Guidelines

### Code Style
- Follow **PEP-8** conventions
- Use **type hints** on all function signatures
- Write **docstrings** for all public functions and classes
- Use `recon.utils.clean_domain()` instead of manual URL parsing
- Return structured **dataclass** instances from recon modules

### Adding a New Module

1. Create `recon/modules/your_module.py`
2. Define a result dataclass (e.g., `YourResult`)
3. Implement a `run(target, ...)` function that returns your dataclass
4. Use `recon.logger.get_logger(__name__)` for logging
5. Register the module in `recon/modules/__init__.py`
6. Add it to `recon/engine.py` in the appropriate execution phase
7. Add scoring rules to `recon/scoring.py` if applicable
8. Update report generators to include your module's output

### Commit Messages
Use clear, descriptive commit messages:
```
feat(dns): add DNSSEC validation check
fix(ssl): handle connection refused on port 443
docs: update installation guide for macOS
```

### Pull Request Process
1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes with tests
3. Ensure the application runs without errors
4. Update documentation if needed
5. Submit a PR with a clear description

## Reporting Issues

When reporting bugs, please include:
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages / traceback

## Code of Conduct

Be respectful and constructive. This is an educational project — all skill levels are welcome.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
