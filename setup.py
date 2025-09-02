from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ai-trust",
    version="0.1.0",
    author="AI Trust Team",
    author_email="team@aitrust.example.com",
    description="AI Accountability Infrastructure",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourorg/ai-trust",
    packages=find_packages(include=["ai_trust", "ai_trust.*"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
    python_requires=">=3.9",
    install_requires=[
        "fastapi>=0.95.0",
        "pydantic>=1.10.0",
        "cryptography>=39.0.0",
        "pyjwt>=2.6.0",
        "httpx>=0.23.0",
        "uvicorn>=0.21.0",
        "typing-extensions>=4.5.0",
        "python-multipart>=0.0.6",
    ],
    extras_require={
        "dev": [
            "pytest>=7.2.0",
            "pytest-cov>=4.0.0",
            "black>=23.1.0",
            "isort>=5.12.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
            "pylint>=2.17.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.10.0",
            "hypothesis>=6.70.0",
            "faker>=17.0.0",
        ],
    },
    entry_points={
        'console_scripts': [
            'aitrust=ai_trust.cli.main:cli',
        ],
    },
)
