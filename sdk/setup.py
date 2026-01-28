"""Setup script for EasyEnclave SDK."""

from setuptools import find_packages, setup

setup(
    name="easyenclave",
    version="0.1.0",
    description="Client library for the EasyEnclave discovery service",
    author="EasyEnclave Team",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "httpx>=0.24.0",
    ],
    extras_require={
        "noise": [
            "noiseprotocol>=0.3.1",
            "cryptography>=41.0.0",
            "websockets>=12.0",
            "fastapi>=0.100.0",
            "requests>=2.28.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
