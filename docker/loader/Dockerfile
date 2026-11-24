FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libaio1 unzip \
    && rm -rf /var/lib/apt/lists/* \
    && curl --fail --show-error --silent --location --retry 3 \
       https://download.oracle.com/otn_software/linux/instantclient/1933000/instantclient-basic-linux.x64-19.33.0.0.0dbru.zip \
       --output /tmp/instantclient.zip \
    && echo 'a2fc1f32b776c1b574c231727d067cca522259c5d8854afdc41caf3ea8f7ef0d  /tmp/instantclient.zip' | sha256sum --check \
    && unzip -q /tmp/instantclient.zip -d /opt/oracle \
    && rm /tmp/instantclient.zip \
    && python -m pip install --no-cache-dir 'oracledb==3.3.0'

ENV LD_LIBRARY_PATH=/opt/oracle/instantclient_19_33 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /workspace
ENTRYPOINT ["python", "-m", "etl.importer"]
