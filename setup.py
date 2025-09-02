from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ai-accountability",
    version="1.0.0",
    author="AI Accountability Project",
    author_email="hello@ai-accountability.org",
    description="A minimal, extensible standard for cryptographically verifiable AI system accountability",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ai-accountability/ai-accountability",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "flask>=2.3.0",
        "python-dateutil>=2.8.2",
        "requests>=2.31.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "mypy>=1.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ai-verify=verifier.verify:main",
            "ai-log=log.server:main",
        ],
    },
)
