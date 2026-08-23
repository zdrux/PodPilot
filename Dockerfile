FROM registry.access.redhat.com/ubi9/python-312@sha256:f3959363d949bb0b7495ffb1c7e3caa36bdbbd665a602fcfee946c46c21f3355

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/app-root/src/apps/api/src:/opt/app-root/src/packages/openshift-client/src \
    PODPILOT_WEB_DIR=/opt/app-root/src/apps/web

WORKDIR /opt/app-root/src

COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock

COPY pyproject.toml ./pyproject.toml
COPY apps/api ./apps/api
COPY apps/web ./apps/web
COPY packages/openshift-client ./packages/openshift-client

USER 0

RUN mkdir -p /var/lib/podpilot && \
    chgrp -R 0 /opt/app-root/src /var/lib/podpilot && \
    chmod -R g=u /opt/app-root/src /var/lib/podpilot

USER 1001

EXPOSE 8080

CMD ["uvicorn", "podpilot_api.main:app", "--host", "127.0.0.1", "--port", "8080", "--no-access-log"]
