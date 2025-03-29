from setuptools import setup, find_packages

setup(
    name="network_scanner",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "Django>=4.2.0",
        "djangorestframework>=3.14.0",
        "django-crispy-forms>=2.0",
        "crispy-bootstrap5>=0.7",
        "django-celery-beat>=2.5.0",
        "django-celery-results>=2.5.0",
        "celery>=5.3.0",
        "redis>=4.5.5",
        "requests>=2.30.0",
        "beautifulsoup4>=4.12.0",
        "python-nmap>=0.7.1",
        "pyOpenSSL>=23.1.1",
        "weasyprint>=59.0",
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="A Django application for network and server scanning",
    keywords="network, scanner, security, monitoring",
    url="https://github.com/yourusername/network_scanner",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Framework :: Django",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking :: Monitoring",
    ],
)

