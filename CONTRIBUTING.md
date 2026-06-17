# Contributing to PQCScanner

Thank you for your interest in contributing to PQCScanner. This guide will help you get started.

## Prerequisites

- Python 3.11+
- Node.js 18+
- Docker and Docker Compose
- PostgreSQL 15+ (if running without Docker)

## Development Setup

### Using Docker (recommended)

```bash
git clone https://github.com/VipinPS/PQCScanner.git
cd PQCScanner
cp .env.example .env  # adjust values as needed
docker-compose up
```

The backend will be available at `http://localhost:8000` and the frontend at `http://localhost:5173`.

### Manual Setup

**Backend:**

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

**Frontend:**

```bash
cd frontend
npm install
npm run dev
```

## Code Style

- **Python:** We use [Ruff](https://github.com/astral-sh/ruff) for linting and [Black](https://github.com/psf/black) for formatting. Run `ruff check .` and `black .` before committing.
- **JavaScript/TypeScript:** We use [Prettier](https://prettier.io/) for formatting. Run `npx prettier --write .` before committing.

## Submitting Changes

1. Fork the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Make your changes and add tests where appropriate.
3. Ensure all tests pass:
   ```bash
   # Backend
   cd backend && pytest

   # Frontend
   cd frontend && npm test
   ```
4. Commit your changes using [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add CRYSTALS-Kyber detection rule
   fix: correct false positive in RSA key size check
   docs: update API endpoint documentation
   ```
5. Push your branch and open a Pull Request against `main`.

## Reporting Issues

- Search existing issues before opening a new one.
- Use the provided issue templates (bug report or feature request).
- Include reproduction steps, expected behavior, and actual behavior for bugs.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md) -- do NOT open a public issue.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this code. Report unacceptable behavior to vipinpinn@gmail.com.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
