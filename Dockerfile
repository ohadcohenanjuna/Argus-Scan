FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install System Dependencies
# nmap: Port scanning
# nikto: Perl app; needs JSON, XML::Writer, SSL (see nikto docs / program/nikto.pl deps)
# git, curl, unzip: Utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    git \
    curl \
    unzip \
    libnet-ssleay-perl \
    libjson-perl \
    libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# Install Nikto (Manual Install since not in simple repositories or unreliable)
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Install Nuclei (ProjectDiscovery)
# Downloading the latest binary release
RUN curl -L https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip -o nuclei.zip \
    && unzip nuclei.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei.zip \
    && nuclei -version

# Set work directory
WORKDIR /app

# Install Python Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Project Files
COPY . .

# Create reports directory
RUN mkdir -p reports

# Entrypoint
ENV PYTHONPATH="${PYTHONPATH}:/app/src"
ENTRYPOINT ["python", "src/vapt.py"]
CMD ["--help"]
